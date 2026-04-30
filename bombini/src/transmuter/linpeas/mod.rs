use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use bombini_common::event::Event;
use bombini_common::event::file::FileEventVariant;

use super::{Transmuter, cache::process::ProcessCache, str_from_bytes};

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct LinPEASConfig {
    pub threshold: usize,
    pub window_sec: u64,
    pub gc_ttl_sec: u64,
    pub alert_cooldown_sec: u64,
    pub signatures: Vec<String>,
    pub url_signatures: Vec<String>,
}

impl Default for LinPEASConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            window_sec: 120,
            gc_ttl_sec: 300,
            alert_cooldown_sec: 60,
            signatures: Vec::new(),
            url_signatures: Vec::new(),
        }
    }
}

pub struct LinPEASTransmuter {
    analyzer: Mutex<LinPEASAnalyzer>,
}

impl LinPEASTransmuter {
    pub fn new(config: LinPEASConfig) -> Self {
        Self {
            analyzer: Mutex::new(LinPEASAnalyzer::new(config)),
        }
    }

    pub fn gc(&self) {
        if let Ok(mut a) = self.analyzer.lock() {
            a.gc();
        }
    }
}

impl Transmuter for LinPEASTransmuter {
    fn transmute(
        &self,
        event: &Event,
        _ktime: u64,
        _process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut analyzer = self
            .analyzer
            .lock()
            .map_err(|_| anyhow!("LinPEAS analyzer mutex poisoned"))?;
        let alert = match event {
            Event::ProcessExec((proc_info, _)) | Event::ProcessClone((proc_info, _)) => {
                let binary = str_from_bytes(&proc_info.binary_path);
                let filename = str_from_bytes(&proc_info.filename);
                let args = str_from_bytes(&proc_info.args);
                analyzer.analyze_exec(&filename, &binary, &args, proc_info.pid, proc_info.ppid)
            }
            Event::File(file_msg) => {
                if let FileEventVariant::FileOpen(ref open) = file_msg.event {
                    let path = str_from_bytes(&open.path);
                    analyzer.analyze_file_open(&path, file_msg.process.pid, file_msg.parent.pid)
                } else {
                    None
                }
            }
            _ => None,
        };
        match alert {
            Some(a) => Ok(serde_json::to_vec(&a)?),
            None => Err(anyhow!("LinPEAS: no alert")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnumCategory {
    SuidSgid,
    Capabilities,
    SensitiveFiles,
    SudoCheck,
    ProcessEnum,
    KernelInfo,
    ContainerInfo,
    NetworkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinPEASAlert {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    pub layer: String,
    pub pid: u32,
    pub ppid: u32,
    pub categories_observed: Vec<String>,
    pub categories_count: usize,
    pub binary: String,
    pub args: String,
}

pub struct LinPEASAnalyzer {
    pub trees: HashMap<u32, HashMap<EnumCategory, Instant>>,
    pub last_alert_per_tree: HashMap<u32, Instant>,
    pub last_signature_per_pattern: HashMap<String, Instant>,
    threshold: usize,
    window_sec: u64,
    gc_ttl_sec: u64,
    cooldown_sec: u64,
    signatures: Vec<String>,
    url_signatures: Vec<String>,
}

impl LinPEASAnalyzer {
    pub fn new(config: LinPEASConfig) -> Self {
        Self {
            trees: HashMap::new(),
            last_alert_per_tree: HashMap::new(),
            last_signature_per_pattern: HashMap::new(),
            threshold: config.threshold,
            window_sec: config.window_sec,
            gc_ttl_sec: config.gc_ttl_sec,
            cooldown_sec: config.alert_cooldown_sec,
            signatures: config.signatures.clone(),
            url_signatures: config.url_signatures.clone(),
        }
    }

    fn signature_alert_allowed(&mut self, pattern: &str) -> bool {
        let now = Instant::now();
        let cooldown = Duration::from_secs(self.cooldown_sec);
        if let Some(last) = self.last_signature_per_pattern.get(pattern) {
            if now.duration_since(*last) < cooldown {
                return false;
            }
        }
        self.last_signature_per_pattern
            .insert(pattern.to_string(), now);
        true
    }

    pub fn analyze_exec(
        &mut self,
        filename: &str,
        binary: &str,
        args: &str,
        pid: u32,
        ppid: u32,
    ) -> Option<LinPEASAlert> {
        if let Some(pat) = self.match_signature(filename, binary, args) {
            if self.signature_alert_allowed(&pat) {
                return Some(Self::build_alert(
                    "signature",
                    pid,
                    ppid,
                    &[],
                    if !filename.is_empty() { filename } else { binary },
                    args,
                ));
            }
        }

        if let Some(cat) = Self::classify_exec(filename, binary, args) {
            return self
                .observe_category(cat, pid, ppid)
                .map(|cats| Self::build_alert("behavioral", pid, ppid, &cats, filename, args));
        }

        None
    }

    pub fn analyze_file_open(&mut self, path: &str, pid: u32, ppid: u32) -> Option<LinPEASAlert> {
        let path_lower = path.to_lowercase();
        let sig_match = self
            .signatures
            .iter()
            .find(|s| path_lower.contains(&s.to_lowercase()))
            .cloned();
        if let Some(pat) = sig_match {
            if self.signature_alert_allowed(&pat) {
                return Some(Self::build_alert("signature", pid, ppid, &[], path, ""));
            }
        }

        if let Some(cat) = Self::classify_file(path) {
            return self
                .observe_category(cat, pid, ppid)
                .map(|cats| Self::build_alert("behavioral", pid, ppid, &cats, path, ""));
        }
        None
    }

    pub fn classify_exec(filename: &str, binary: &str, args: &str) -> Option<EnumCategory> {
        let bin_name = if !filename.is_empty() {
            filename
        } else {
            binary.rsplit('/').next().unwrap_or(binary)
        };

        match bin_name {
            "find" => {
                if args.contains("-perm")
                    && (args.contains("4000")
                        || args.contains("2000")
                        || args.contains("u+s")
                        || args.contains("g+s")
                        || args.contains("/6000")
                        || args.contains("/4000"))
                {
                    return Some(EnumCategory::SuidSgid);
                }
                if args.contains("-writable")
                    || args.contains(".pem")
                    || args.contains(".key")
                    || args.contains("authorized_keys")
                    || args.contains("id_rsa")
                    || args.contains("id_dsa")
                {
                    return Some(EnumCategory::SensitiveFiles);
                }
                if args.contains("/proc/")
                    && (args.contains("-regex") || args.contains("/proc/[0-9]"))
                {
                    return Some(EnumCategory::ProcessEnum);
                }
            }
            "getcap" => {
                if args.contains("-r") || args.contains("/") {
                    return Some(EnumCategory::Capabilities);
                }
            }
            "sudo" => {
                let a = args.trim();
                if a == "-l"
                    || a == "-ll"
                    || a == "-V"
                    || a == "-nl"
                    || a == "-n -l"
                    || a.starts_with("-l ")
                    || a.starts_with("-ll ")
                    || a.ends_with(" -l")
                    || a.ends_with(" -V")
                {
                    return Some(EnumCategory::SudoCheck);
                }
            }
            "ps" => {
                if args.contains("aux")
                    || args.contains("-ef")
                    || args.contains("-eo")
                    || args.contains("-ax")
                    || args.contains("-Af")
                    || args.contains("-fA")
                {
                    return Some(EnumCategory::ProcessEnum);
                }
            }
            "uname" => {
                if args.contains("-a") || args.contains("-r") || args.contains("-v") {
                    return Some(EnumCategory::KernelInfo);
                }
            }
            "ss" => {
                if args.contains("-t")
                    || args.contains("-u")
                    || args.contains("-l")
                    || args.contains("-n")
                    || args.contains("-p")
                    || args.contains("-a")
                {
                    return Some(EnumCategory::NetworkInfo);
                }
            }
            "netstat" => {
                if args.contains("-t")
                    || args.contains("-u")
                    || args.contains("-l")
                    || args.contains("-n")
                    || args.contains("-p")
                    || args.contains("-a")
                {
                    return Some(EnumCategory::NetworkInfo);
                }
            }
            "ip" => {
                if args.contains("route") || args.contains("addr") || args.contains("link") {
                    return Some(EnumCategory::NetworkInfo);
                }
            }
            "lsb_release" => {
                if args.contains("-a") || args.contains("-d") {
                    return Some(EnumCategory::KernelInfo);
                }
            }
            "mount" => {
                if args.trim().is_empty() || args.contains("-l") || args.contains("-t") {
                    return Some(EnumCategory::SensitiveFiles);
                }
            }
            "crontab" => {
                if args.contains("-l") {
                    return Some(EnumCategory::SensitiveFiles);
                }
            }
            "cat" | "head" | "tail" | "less" | "more" | "strings" => {
                if args.contains("/etc/shadow")
                    || args.contains("/etc/gshadow")
                    || args.contains("/etc/sudoers")
                    || args.contains("/etc/crontab")
                    || args.contains("/etc/passwd")
                {
                    return Some(EnumCategory::SensitiveFiles);
                }
                if args.contains("/.dockerenv") || args.contains("kubernetes.io") {
                    return Some(EnumCategory::ContainerInfo);
                }
                if args.contains("/proc/version")
                    || args.contains("/proc/sys/kernel/")
                    || args.contains("/etc/os-release")
                    || args.contains("/etc/issue")
                {
                    return Some(EnumCategory::KernelInfo);
                }
                if args.contains("/etc/cron.")
                    || args.contains("/var/spool/cron")
                    || args.contains("/etc/anacrontab")
                {
                    return Some(EnumCategory::SensitiveFiles);
                }
            }
            _ => {}
        }

        None
    }

    pub fn classify_file(path: &str) -> Option<EnumCategory> {
        match path {
            "/etc/shadow" | "/etc/sudoers" | "/etc/gshadow" | "/etc/crontab" | "/etc/passwd-"
            | "/etc/shadow-" => Some(EnumCategory::SensitiveFiles),
            "/proc/version" | "/proc/sys/kernel/version" => Some(EnumCategory::KernelInfo),
            "/.dockerenv" | "/run/.containerenv" => Some(EnumCategory::ContainerInfo),
            _ => {
                if path.starts_with("/run/secrets/kubernetes.io")
                    || path.starts_with("/var/run/secrets/kubernetes.io")
                {
                    Some(EnumCategory::ContainerInfo)
                } else if path.starts_with("/etc/sudoers.d/") {
                    Some(EnumCategory::SensitiveFiles)
                } else {
                    None
                }
            }
        }
    }

    pub fn match_signature(
        &self,
        filename: &str,
        binary: &str,
        args: &str,
    ) -> Option<String> {
        let combined = format!("{} {} {}", filename, binary, args).to_lowercase();
        for sig in &self.signatures {
            if combined.contains(&sig.to_lowercase()) {
                return Some(sig.clone());
            }
        }
        for url_sig in &self.url_signatures {
            if combined.contains(&url_sig.to_lowercase()) {
                return Some(url_sig.clone());
            }
        }
        None
    }

    pub fn check_signature(&self, filename: &str, binary: &str, args: &str) -> bool {
        self.match_signature(filename, binary, args).is_some()
    }

    pub fn gc(&mut self) {
        let ttl = Duration::from_secs(self.gc_ttl_sec);
        let now = Instant::now();
        for bucket in self.trees.values_mut() {
            bucket.retain(|_, t| now.duration_since(*t) < ttl);
        }
        self.trees.retain(|_, b| !b.is_empty());
        self.last_alert_per_tree
            .retain(|_, t| now.duration_since(*t) < ttl);
        self.last_signature_per_pattern
            .retain(|_, t| now.duration_since(*t) < ttl);
    }

    fn observe_category(
        &mut self,
        category: EnumCategory,
        pid: u32,
        ppid: u32,
    ) -> Option<Vec<String>> {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_sec);
        let cooldown = Duration::from_secs(self.cooldown_sec);

        let mut keys: Vec<u32> = Vec::with_capacity(2);
        if pid > 1 {
            keys.push(pid);
        }
        if ppid > 1 && ppid != pid {
            keys.push(ppid);
        }
        if keys.is_empty() {
            return None;
        }

        for key in keys {
            let bucket = self.trees.entry(key).or_default();
            bucket.insert(category, now);
            bucket.retain(|_, t| now.duration_since(*t) < window);

            if bucket.len() < self.threshold {
                continue;
            }

            if let Some(last) = self.last_alert_per_tree.get(&key) {
                if now.duration_since(*last) < cooldown {
                    continue;
                }
            }

            let cats: Vec<String> = bucket.keys().map(|c| format!("{:?}", c)).collect();
            self.last_alert_per_tree.insert(key, now);
            bucket.clear();
            return Some(cats);
        }
        None
    }

    fn build_alert(
        layer: &str,
        pid: u32,
        ppid: u32,
        categories: &[String],
        binary: &str,
        args: &str,
    ) -> LinPEASAlert {
        LinPEASAlert {
            event_type: "LinPEASAlert".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            layer: layer.to_string(),
            pid,
            ppid,
            categories_count: categories.len(),
            categories_observed: categories.to_vec(),
            binary: binary.to_string(),
            args: args.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LinPEASConfig {
        LinPEASConfig {
            threshold: 3,
            window_sec: 120,
            gc_ttl_sec: 1,
            alert_cooldown_sec: 0,
            signatures: vec!["linpeas".into(), "PEASS-ng".into()],
            url_signatures: vec!["linpeas.sh".into()],
        }
    }

    #[test]
    fn classify_exec_suid() {
        assert_eq!(
            LinPEASAnalyzer::classify_exec("find", "", "-perm -4000 /"),
            Some(EnumCategory::SuidSgid)
        );
    }

    #[test]
    fn classify_exec_capabilities() {
        assert_eq!(
            LinPEASAnalyzer::classify_exec("getcap", "", "-r /"),
            Some(EnumCategory::Capabilities)
        );
    }

    #[test]
    fn classify_exec_sudo_l() {
        assert_eq!(
            LinPEASAnalyzer::classify_exec("sudo", "", "-l"),
            Some(EnumCategory::SudoCheck)
        );
        assert_eq!(
            LinPEASAnalyzer::classify_exec("sudo", "", "cat /etc/hosts"),
            None
        );
    }

    #[test]
    fn classify_file_sensitive() {
        assert_eq!(
            LinPEASAnalyzer::classify_file("/etc/shadow"),
            Some(EnumCategory::SensitiveFiles)
        );
        assert_eq!(
            LinPEASAnalyzer::classify_file("/.dockerenv"),
            Some(EnumCategory::ContainerInfo)
        );
        assert_eq!(LinPEASAnalyzer::classify_file("/etc/hosts"), None);
    }

    #[test]
    fn signature_matches_filename() {
        let analyzer = LinPEASAnalyzer::new(test_config());
        assert!(analyzer.check_signature("linpeas.sh", "", ""));
        assert!(analyzer.check_signature("", "/tmp/linpeas", ""));
        assert!(!analyzer.check_signature("ls", "/usr/bin/ls", "-la"));
    }

    #[test]
    fn signature_matches_args() {
        let analyzer = LinPEASAnalyzer::new(test_config());
        assert!(analyzer.check_signature("bash", "", "/tmp/linpeas.sh -a"));
        assert!(analyzer.check_signature("curl", "", "https://x/linpeas.sh"));
    }

    #[test]
    fn signature_alert_immediate() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        let alert = analyzer.analyze_exec("linpeas.sh", "", "-a", 100, 1);
        let alert = alert.unwrap();
        assert_eq!(alert.layer, "signature");
        assert_eq!(alert.pid, 100);
    }

    #[test]
    fn behavioral_alert_below_threshold() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        assert!(
            analyzer
                .analyze_exec("find", "", "-perm -4000 /", 100, 50)
                .is_none()
        );
        assert!(analyzer.analyze_exec("uname", "", "-a", 101, 50).is_none());
    }

    #[test]
    fn behavioral_alert_per_parent_tree() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        assert!(
            analyzer
                .analyze_exec("find", "", "-perm -4000 /", 1001, 1000)
                .is_none()
        );
        assert!(
            analyzer
                .analyze_exec("uname", "", "-a", 1002, 1000)
                .is_none()
        );
        let alert = analyzer.analyze_exec("ss", "", "-tlnp", 1003, 1000);
        let alert = alert.unwrap();
        assert_eq!(alert.layer, "behavioral");
        assert_eq!(alert.categories_count, 3);
    }

    #[test]
    fn behavioral_alert_isolated_per_tree() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        analyzer.analyze_exec("find", "", "-perm -4000 /", 2001, 2000);
        analyzer.analyze_exec("uname", "", "-a", 2002, 2000);
        assert!(
            analyzer
                .analyze_exec("ss", "", "-tlnp", 3003, 3000)
                .is_none(),
            "different tree must not piggyback on another tree's counters"
        );
    }

    #[test]
    fn behavioral_alert_via_file_open() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        analyzer.analyze_exec("ps", "", "aux", 4001, 4000);
        analyzer.analyze_file_open("/etc/shadow", 4002, 4000);
        let alert = analyzer.analyze_file_open("/.dockerenv", 4003, 4000);
        assert!(alert.is_some());
    }

    #[test]
    fn alert_resets_only_one_tree() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        analyzer.analyze_exec("find", "", "-perm -4000 /", 5001, 5000);
        analyzer.analyze_exec("uname", "", "-a", 5002, 5000);
        let _ = analyzer.analyze_exec("ss", "", "-tlnp", 5003, 5000);
        let bucket = analyzer.trees.get(&5000).cloned().unwrap_or_default();
        assert!(bucket.is_empty(), "parent bucket must be cleared after alert");
    }

    #[test]
    fn cooldown_blocks_duplicate_alerts_in_same_tree() {
        let cfg = LinPEASConfig {
            threshold: 2,
            window_sec: 120,
            gc_ttl_sec: 60,
            alert_cooldown_sec: 60,
            signatures: vec![],
            url_signatures: vec![],
        };
        let mut analyzer = LinPEASAnalyzer::new(cfg);
        analyzer.analyze_exec("find", "", "-perm -4000 /", 6001, 6000);
        let first = analyzer.analyze_exec("uname", "", "-a", 6002, 6000);
        assert!(first.is_some());
        analyzer.analyze_exec("find", "", "-perm -4000 /", 6003, 6000);
        let second = analyzer.analyze_exec("uname", "", "-a", 6004, 6000);
        assert!(second.is_none());
    }

    #[test]
    fn signature_cooldown_global_per_pattern() {
        let cfg = LinPEASConfig {
            threshold: 3,
            window_sec: 120,
            gc_ttl_sec: 60,
            alert_cooldown_sec: 60,
            signatures: vec![],
            url_signatures: vec!["linpeas.sh".into()],
        };
        let mut analyzer = LinPEASAnalyzer::new(cfg);
        let a1 = analyzer.analyze_exec("bash", "", "/tmp/linpeas.sh", 100, 99);
        assert!(a1.is_some(), "first signature alert");
        let a2 = analyzer.analyze_exec("bash", "", "/tmp/linpeas.sh", 200, 199);
        assert!(
            a2.is_none(),
            "same pattern from different tree must be blocked by global cooldown to prevent flood"
        );
        let a3 = analyzer.analyze_exec("cat", "", "/tmp/linpeas.sh", 300, 299);
        assert!(
            a3.is_none(),
            "same matched pattern (linpeas.sh) regardless of binary must be blocked"
        );
    }

    #[test]
    fn gc_removes_stale_trees() {
        let mut analyzer = LinPEASAnalyzer::new(test_config());
        analyzer.analyze_exec("find", "", "-perm -4000 /", 7001, 7000);
        std::thread::sleep(Duration::from_millis(1100));
        analyzer.gc();
        assert!(analyzer.trees.is_empty());
    }
}
