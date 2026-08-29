//! Transmutes Process to serializable struct

use anyhow::anyhow;
use base64::Engine;
use std::sync::Arc;

use bombini_common::event::{
    Event,
    process::{
        Capabilities, Cgroup, ImaHash, LsmSetIdFlags, PrctlCmd, ProcBprmCheck, ProcCapset,
        ProcInfo, ProcPrctl, ProcPtraceAccessCheck, ProcSetGid, ProcSetUid, ProcessEventVariant,
        ProcessKey, PtraceMode, SecureExec,
    },
};

use serde::{Serialize, Serializer};

use crate::proto::config::{HookConfig, ProcMonConfig};

use super::{
    Transmuter,
    cache::process::{CachedProcess, ProcessCache},
    str_from_bytes, transmute_ktime,
};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
/// Process exec event
pub struct ProcessExec {
    /// Process information
    process: Arc<Process>,
    /// Parent Process information
    parent: Option<Arc<Process>>,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
/// Process clone event
pub struct ProcessClone {
    /// Process information
    process: Arc<Process>,
    /// Parent Process information
    parent: Option<Arc<Process>>,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
/// Process exit event
pub struct ProcessExit {
    /// Process information
    process: Arc<Process>,
    /// Parent Process information
    parent: Option<Arc<Process>>,
    /// Event's date and time
    timestamp: String,
}

/// Process information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Process {
    /// last exec or clone time
    pub start_time: String,
    /// is process cloned without exec
    pub cloned: bool,
    /// PID
    pub pid: u32,
    /// TID
    pub tid: u32,
    /// Parent PID
    pub ppid: u32,
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    /// GID
    pub gid: u32,
    /// EGID
    pub egid: u32,
    /// login UID
    pub auid: u32,
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub cap_inheritable: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub cap_permitted: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub cap_effective: Capabilities,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    /// SETUID, SETGID, FILECAPS, FILELESS_EXEC
    pub secureexec: SecureExec,
    /// executable name
    pub filename: String,
    /// full binary path
    pub binary_path: String,
    /// current work directory
    pub args: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    /// skip for host
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub container_id: String,
    /// IMA binary hash
    #[serde(skip_serializing_if = "is_invalid_ima")]
    #[serde(serialize_with = "serialize_ima")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub binary_ima_hash: ImaHash,
    /// Execution ID (hash of the process's PID and start time)
    pub exec_id: String,
    /// Parent execution ID (hash of the parent's PID and start time)
    pub parent_exec_id: String,
}

/// Setuid event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessSetUid {
    euid: u32,
    uid: u32,
    fsuid: u32,
    /// LSM_SETID_* flag values
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    flags: LsmSetIdFlags,
}

/// Setgid event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessSetGid {
    egid: u32,
    gid: u32,
    fsgid: u32,
    /// LSM_SETID_* flag values
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    flags: LsmSetIdFlags,
}

/// Capset event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessCapset {
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub inheritable: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub permitted: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub effective: Capabilities,
}

/// Prctl event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessPrctl {
    cmd: PrctlCmdUser,
}

/// Enumeration of prctl supported commands
#[derive(Clone, Debug, Serialize)]
#[repr(u8)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PrctlCmdUser {
    Opcode(u8) = 0,
    PrSetDumpable(u8) = 4,
    PrSetKeepCaps(u8) = 8,
    PrSetName { name: String } = 15,
    PrSetSecurebits(u32) = 28,
}

/// Bprm_check event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessBprmCheck {
    binary: String,
}

fn serialize_capabilities<S>(caps: &Capabilities, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *caps == Capabilities::ANY_CAPS {
        serializer.serialize_str("ANY_CAPS")
    } else {
        caps.serialize(serializer)
    }
}

fn serialize_ima<S>(ima: &ImaHash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match ima.algo {
        1 => {
            // MD5
            let hash_str = format!(
                "md5:{}",
                ima.hash[..16]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        2 => {
            // SHA1
            let hash_str = format!(
                "sha1:{}",
                ima.hash[..20]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        4 => {
            // SHA256
            let hash_str = format!(
                "sha256:{}",
                ima.hash[..32]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        6 => {
            // SHA512
            let hash_str = format!(
                "sha512:{}",
                ima.hash
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        13 => {
            // WP512
            let hash_str = format!(
                "wp512:{}",
                ima.hash
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        17 => {
            // SM3
            let hash_str = format!(
                "sm3:{}",
                ima.hash[..32]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            serializer.serialize_str(&hash_str)
        }
        _ => {
            let hash_str = String::new();
            serializer.serialize_str(&hash_str)
        }
    }
}

fn is_invalid_ima(ima: &ImaHash) -> bool {
    ima.algo <= 0
}

/// Minimal container id length. It could be truncated in ebpf.
pub const CONTAINER_ID_LENGTH: usize = 31;

fn container_id_from_cgroup(cgroup: &Cgroup) -> String {
    let cgroup_name = str_from_bytes(&cgroup.cgroup_name);
    let container = cgroup_name
        .split(':')
        .next_back()
        .unwrap_or("")
        .split('-')
        .next_back()
        .unwrap_or("");

    if container.ends_with(".service") {
        return String::new();
    }

    // Reject non hex leftovers: cgroup_name holds a full cgroup path
    // for processes discovered via procfs.
    let bytes = container.as_bytes();
    if bytes.len() < CONTAINER_ID_LENGTH
        || !bytes[..CONTAINER_ID_LENGTH]
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        return String::new();
    }
    container[..CONTAINER_ID_LENGTH].to_string()
}

/// Generate base64 hash from process's PID and start time
fn get_exec_id(process_key: &ProcessKey) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .encode(format!("{}:{}", process_key.pid, process_key.start))
}

/// CreateUserNs event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessCreateUserNs {}

/// PtraceAttach event
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessPtraceAccessCheck {
    child: Process,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    mode: PtraceMode,
}

impl Process {
    /// Constructs High level event representation from low eBPF
    pub fn new(proc: &ProcInfo, parent_key: &ProcessKey) -> Self {
        let mut args = proc.args;
        args.iter_mut().for_each(|e| {
            if *e == 0x00 {
                *e = 0x20
            }
        });
        let process_key = ProcessKey {
            pid: proc.pid,
            start: proc.start,
        };
        let args = String::from_utf8_lossy(&args).trim_end().to_string();
        Self {
            start_time: transmute_ktime(proc.start),
            cloned: proc.cloned,
            pid: proc.pid,
            tid: proc.tid,
            ppid: proc.ppid,
            auid: proc.auid,
            uid: proc.creds.uid,
            euid: proc.creds.euid,
            gid: proc.creds.gid,
            egid: proc.creds.egid,
            cap_effective: proc.creds.cap_effective,
            cap_permitted: proc.creds.cap_permitted,
            cap_inheritable: proc.creds.cap_inheritable,
            secureexec: SecureExec::from_bits_truncate(proc.creds.secureexec.bits()),
            filename: str_from_bytes(&proc.filename),
            binary_path: str_from_bytes(&proc.binary_path),
            args,
            container_id: container_id_from_cgroup(&proc.cgroup),
            binary_ima_hash: proc.ima_hash,
            exec_id: get_exec_id(&process_key),
            parent_exec_id: get_exec_id(parent_key),
        }
    }
}

impl ProcessExec {
    /// Constructs High level event representation from low eBPF message
    pub fn new(process: Arc<Process>, ktime: u64, parent: Option<Arc<Process>>) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process,
            parent,
        }
    }
}

pub struct ProcessExecTransmuter;

impl Transmuter for ProcessExecTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcessExec((event_proc, parent_key)) = event {
            // Remove previous Process record
            let prev_key = ProcessKey {
                pid: event_proc.pid,
                start: event_proc.prev_start,
            };
            if let Some(cached_process) = process_cache.get_mut(&prev_key) {
                cached_process.exited = true;
            } else {
                log::debug!(
                    "ProcessExec: No previous Process record (pid: {}, start: {}) found in cache",
                    event_proc.pid,
                    transmute_ktime(event_proc.prev_start)
                );
            }

            // Add new one after exec
            let process = Arc::new(Process::new(event_proc, parent_key));
            let key = ProcessKey {
                pid: event_proc.pid,
                start: event_proc.start,
            };
            let cached_process = CachedProcess {
                process: process.clone(),
                exited: false,
            };
            process_cache.insert(key, cached_process);
            let parent = if let Some(cached_process) = process_cache.get(parent_key) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "ProcessExec: No parent Process record (pid: {}, start: {}) found in cache",
                    parent_key.pid,
                    transmute_ktime(parent_key.start)
                );
                None
            };
            let high_level_event = ProcessExec::new(process, ktime, parent);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

impl ProcessClone {
    /// Constructs High level event representation from low eBPF message
    pub fn new(process: Arc<Process>, ktime: u64, parent: Option<Arc<Process>>) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process,
            parent,
        }
    }
}

pub struct ProcessCloneTransmuter;

impl Transmuter for ProcessCloneTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcessClone((event_proc, parent_key)) = event {
            let process = Arc::new(Process::new(event_proc, parent_key));
            let key = ProcessKey {
                pid: event_proc.pid,
                start: event_proc.start,
            };
            let cached_process = CachedProcess {
                process: process.clone(),
                exited: false,
            };
            process_cache.insert(key, cached_process);
            let parent = if let Some(cached_process) = process_cache.get(parent_key) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "ProcessClone: No parent Process record (pid: {}, start: {}) found in cache",
                    parent_key.pid,
                    transmute_ktime(parent_key.start)
                );
                None
            };
            let high_level_event = ProcessClone::new(process.clone(), ktime, parent);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

impl ProcessExit {
    /// Constructs High level event representation from low eBPF message
    pub fn new(process: Arc<Process>, ktime: u64, parent: Option<Arc<Process>>) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process,
            parent,
        }
    }
}

pub struct ProcessExitTransmuter;

impl Transmuter for ProcessExitTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcessExit((event_key, parent_key)) = event {
            let parent = if let Some(cached_process) = process_cache.get(parent_key) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "ProcessExit: No parent Process record (pid: {}, start: {}) found in cache",
                    parent_key.pid,
                    transmute_ktime(parent_key.start)
                );
                None
            };
            if let Some(cached_process) = process_cache.get_mut(event_key) {
                cached_process.exited = true;
                let high_level_event =
                    ProcessExit::new(cached_process.process.clone(), ktime, parent);
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "ProcessExit: No process (pid: {}, start: {}) found in cache",
                    event_key.pid,
                    transmute_ktime(event_key.start)
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

impl ProcessSetUid {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcSetUid) -> Self {
        Self {
            uid: event.uid,
            euid: event.euid,
            fsuid: event.fsuid,
            flags: event.flags.clone(),
        }
    }
}

impl ProcessSetGid {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcSetGid) -> Self {
        Self {
            gid: event.gid,
            egid: event.egid,
            fsgid: event.fsgid,
            flags: event.flags.clone(),
        }
    }
}

impl ProcessCapset {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcCapset) -> Self {
        Self {
            effective: event.effective,
            inheritable: event.inheritable,
            permitted: event.permitted,
        }
    }
}
impl ProcessPrctl {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcPrctl) -> Self {
        let cmd = match event.cmd {
            PrctlCmd::Opcode(op) => PrctlCmdUser::Opcode(op),
            PrctlCmd::PrSetDumpable(v) => PrctlCmdUser::PrSetDumpable(v),
            PrctlCmd::PrSetKeepCaps(v) => PrctlCmdUser::PrSetKeepCaps(v),
            PrctlCmd::PrSetSecurebits(v) => PrctlCmdUser::PrSetSecurebits(v),
            PrctlCmd::PrSetName { name } => PrctlCmdUser::PrSetName {
                name: str_from_bytes(&name),
            },
        };
        Self { cmd }
    }
}

impl ProcessPtraceAccessCheck {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcPtraceAccessCheck, parent_key: &ProcessKey) -> Self {
        Self {
            child: Process::new(&event.child, parent_key),
            mode: event.mode.clone(),
        }
    }
}

impl ProcessBprmCheck {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcBprmCheck) -> Self {
        Self {
            binary: str_from_bytes(&event.binary),
        }
    }
}

/// Process Event
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct ProcessEvent<'a> {
    /// Process information
    process: Arc<Process>,
    /// Parent process information
    parent: Option<Arc<Process>>,
    /// If event is blocked by sandbox mode
    blocked: bool,
    /// Process event
    process_event: ProcessEventType,
    /// Event's date and time
    timestamp: String,
    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[allow(clippy::large_enum_variant)]
/// Process event types
pub enum ProcessEventType {
    Setuid(ProcessSetUid),
    Setgid(ProcessSetGid),
    Setcaps(ProcessCapset),
    Prctl(ProcessPrctl),
    CreateUserNs(ProcessCreateUserNs),
    PtraceAccessCheck(ProcessPtraceAccessCheck),
    BprmCheck(ProcessBprmCheck),
    ExecveSandbox,
}

impl<'a> ProcessEvent<'a> {
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        parent_key: &ProcessKey,
        blocked: bool,
        event: &ProcessEventVariant,
        rule: Option<&'a str>,
        ktime: u64,
    ) -> Self {
        match event {
            ProcessEventVariant::Setuid(proc) => Self {
                process_event: ProcessEventType::Setuid(ProcessSetUid::new(proc)),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Setgid(proc) => Self {
                process_event: ProcessEventType::Setgid(ProcessSetGid::new(proc)),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Setcaps(proc) => Self {
                process_event: ProcessEventType::Setcaps(ProcessCapset::new(proc)),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Prctl(proc) => Self {
                process_event: ProcessEventType::Prctl(ProcessPrctl::new(proc)),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::CreateUserNs => Self {
                process_event: ProcessEventType::CreateUserNs(ProcessCreateUserNs {}),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::PtraceAccessCheck(proc) => Self {
                process_event: ProcessEventType::PtraceAccessCheck(ProcessPtraceAccessCheck::new(
                    proc, parent_key,
                )),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::BprmCheck(proc) => Self {
                process_event: ProcessEventType::BprmCheck(ProcessBprmCheck::new(proc)),
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::ExecveSandbox => Self {
                process_event: ProcessEventType::ExecveSandbox,
                process,
                parent,
                rule,
                blocked,
                timestamp: transmute_ktime(ktime),
            },
        }
    }
}

pub struct ProcessEventTransmuter {
    setuid_rule_names: Vec<String>,
    setgid_rule_names: Vec<String>,
    setcaps_rule_names: Vec<String>,
    prctl_rule_names: Vec<String>,
    create_user_ns_rule_names: Vec<String>,
    ptrace_access_check_rule_names: Vec<String>,
    bprm_check_rule_names: Vec<String>,
    execve_sandbox_rule_names: Vec<String>,
}

impl ProcessEventTransmuter {
    pub fn new(cfg: &ProcMonConfig) -> Self {
        #[inline(always)]
        fn rule_names_from_hook_config(hook: &Option<HookConfig>) -> Vec<String> {
            hook.as_ref().map_or(Vec::new(), |hcfg| {
                hcfg.rules.iter().map(|x| x.name.clone()).collect()
            })
        }

        Self {
            setuid_rule_names: rule_names_from_hook_config(&cfg.setuid),
            setgid_rule_names: rule_names_from_hook_config(&cfg.setgid),
            setcaps_rule_names: rule_names_from_hook_config(&cfg.capset),
            prctl_rule_names: rule_names_from_hook_config(&cfg.prctl),
            create_user_ns_rule_names: rule_names_from_hook_config(&cfg.create_user_ns),
            ptrace_access_check_rule_names: rule_names_from_hook_config(&cfg.ptrace_access_check),
            bprm_check_rule_names: rule_names_from_hook_config(&cfg.bprm_check),
            execve_sandbox_rule_names: rule_names_from_hook_config(&cfg.sched_process_exec),
        }
    }

    fn get_rule_name(
        &self,
        process_event: &ProcessEventVariant,
        rule_idx: Option<u8>,
    ) -> Result<Option<&str>, anyhow::Error> {
        let rule_names = match process_event {
            ProcessEventVariant::Setuid(_) => &self.setuid_rule_names,
            ProcessEventVariant::Setgid(_) => &self.setgid_rule_names,
            ProcessEventVariant::Setcaps(_) => &self.setcaps_rule_names,
            ProcessEventVariant::Prctl(_) => &self.prctl_rule_names,
            ProcessEventVariant::CreateUserNs => &self.create_user_ns_rule_names,
            ProcessEventVariant::PtraceAccessCheck(_) => &self.ptrace_access_check_rule_names,
            ProcessEventVariant::BprmCheck(_) => &self.bprm_check_rule_names,
            ProcessEventVariant::ExecveSandbox => &self.execve_sandbox_rule_names,
        };

        rule_idx
            .map(|idx| {
                rule_names
                    .get(idx as usize)
                    .map(|x| x.as_str())
                    .ok_or(anyhow::anyhow!(
                        "ProcessEvent: No rule name found for rule index: {}",
                        idx
                    ))
            })
            .transpose()
    }
}

impl Transmuter for ProcessEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::Process(msg) = event {
            let parent = if let Some(cached_process) = process_cache.get(&msg.parent) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "ProcessEvent: No parent Process record (pid: {}, start: {}) found in cache",
                    msg.parent.pid,
                    transmute_ktime(msg.parent.start)
                );
                None
            };
            if let Some(cached_process) = process_cache.get_mut(&msg.process) {
                let rule_name = match self.get_rule_name(&msg.event, msg.rule_idx) {
                    Ok(rule_name) => rule_name,
                    Err(e) => {
                        log::warn!("Could not determine rule name, error: {e}");
                        None
                    }
                };
                let high_level_event = ProcessEvent::new(
                    cached_process.process.clone(),
                    parent,
                    &msg.parent,
                    msg.blocked,
                    &msg.event,
                    rule_name,
                    ktime,
                );
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "ProcessEvent: No process (pid: {}, start: {}) found in cache",
                    msg.process.pid,
                    transmute_ktime(msg.process.start)
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bombini_common::constants::DOCKER_ID_LENGTH;

    fn cgroup(name: &str) -> Cgroup {
        let mut cgroup_name = [0u8; DOCKER_ID_LENGTH];
        let bytes = name.as_bytes();
        let len = bytes.len().min(DOCKER_ID_LENGTH);
        cgroup_name[..len].copy_from_slice(&bytes[..len]);
        Cgroup {
            cgroup_id: 0,
            cgroup_name,
        }
    }

    const ID: &str = "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345678a";

    #[test]
    fn container_id_from_ebpf_cgroup_name() {
        // containerd/CRI-O/docker with systemd driver
        for leaf in [
            format!("cri-containerd-{ID}.scope"),
            format!("crio-{ID}.scope"),
            format!("docker-{ID}.scope"),
        ] {
            assert_eq!(
                container_id_from_cgroup(&cgroup(&leaf)),
                ID[..CONTAINER_ID_LENGTH]
            );
        }
        // containerd systemd form: slice:prefix:name
        assert_eq!(
            container_id_from_cgroup(&cgroup(&format!(
                "kubepods-besteffort.slice:cri-containerd:{ID}"
            ))),
            ID[..CONTAINER_ID_LENGTH]
        );
        // cgroupfs driver
        assert_eq!(
            container_id_from_cgroup(&cgroup(ID)),
            ID[..CONTAINER_ID_LENGTH]
        );
    }

    #[test]
    fn container_id_is_empty_for_host() {
        for name in [
            "",
            "sshd.service",
            "session-3.scope",
            "nvidia-persistenced.service",
            "init.scope",
            &ID[..16],
        ] {
            assert!(container_id_from_cgroup(&cgroup(name)).is_empty(), "{name}");
        }
    }

    #[test]
    fn container_id_is_empty_for_procfs_path() {
        // ProcInfo::from_procfs puts a full cgroup path into cgroup_name
        for name in [
            format!("/kubepods/burstable/pod4a5b6c7d-8e9f-40a1-b2c3-d4e5f6071829/{ID}"),
            format!(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod4a5b6c7d_8e9f_40a1_b2c3_d4e5f6071829.slice/cri-containerd-{ID}.scope"
            ),
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice"
                .to_string(),
        ] {
            assert!(
                container_id_from_cgroup(&cgroup(&name)).is_empty(),
                "{name}"
            );
        }
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::{ProcessClone, ProcessEvent, ProcessExec, ProcessExit};
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_procmon_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&event_ref)
            .unwrap();
        let _ = writeln!(file, "## ProcMon\n\n```json");
        let schema = schemars::schema_for!(ProcessExec);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let schema = schemars::schema_for!(ProcessClone);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let schema = schemars::schema_for!(ProcessExit);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let schema = schemars::schema_for!(ProcessEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
