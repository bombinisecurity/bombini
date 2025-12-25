//! Transmutes Process to serializable struct

use anyhow::anyhow;
use async_trait::async_trait;
use std::sync::Arc;

use bombini_common::event::{
    Event,
    process::{
        Capabilities, Cgroup, ImaHash, LsmSetIdFlags, PrctlCmd, ProcCapset, ProcInfo, ProcPrctl,
        ProcPtraceAccessCheck, ProcSetGid, ProcSetUid, ProcessEventVariant, ProcessKey, PtraceMode,
        SecureExec,
    },
};

use serde::{Serialize, Serializer};

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

fn serialize_capabilities<S>(caps: &Capabilities, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *caps == Capabilities::ALL_CAPS {
        serializer.serialize_str("ALL_CAPS")
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

fn container_id_from_cgroup(cgroup: &Cgroup) -> String {
    let container = str_from_bytes(&cgroup.cgroup_name)
        .split(':')
        .next_back()
        .unwrap_or("")
        .split('-')
        .next_back()
        .unwrap_or("")
        .to_string();

    if container.ends_with(".service") {
        return String::new();
    }

    // Minimal container id length. It could be truncated in ebpf.
    if container.len() >= 31 {
        container[..31].to_string()
    } else {
        String::new()
    }
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
    pub fn new(proc: &ProcInfo) -> Self {
        let mut args = proc.args;
        args.iter_mut().for_each(|e| {
            if *e == 0x00 {
                *e = 0x20
            }
        });
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

#[async_trait]
impl Transmuter for ProcessExecTransmuter {
    async fn transmute(
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
            let process = Arc::new(Process::new(event_proc));
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

#[async_trait]
impl Transmuter for ProcessCloneTransmuter {
    async fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcessClone((event_proc, parent_key)) = event {
            let process = Arc::new(Process::new(event_proc));
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

#[async_trait]
impl Transmuter for ProcessExitTransmuter {
    async fn transmute(
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
    pub fn new(event: &ProcPtraceAccessCheck) -> Self {
        Self {
            child: Process::new(&event.child),
            mode: event.mode.clone(),
        }
    }
}

/// Process Event
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcessEvent {
    /// Process information
    process: Arc<Process>,
    /// Parent process information
    parent: Option<Arc<Process>>,
    /// Process event
    process_event: ProcessEventType,
    /// Event's date and time
    timestamp: String,
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
}

impl ProcessEvent {
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        event: &ProcessEventVariant,
        ktime: u64,
    ) -> Self {
        match event {
            ProcessEventVariant::Setuid(proc) => Self {
                process_event: ProcessEventType::Setuid(ProcessSetUid::new(proc)),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Setgid(proc) => Self {
                process_event: ProcessEventType::Setgid(ProcessSetGid::new(proc)),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Setcaps(proc) => Self {
                process_event: ProcessEventType::Setcaps(ProcessCapset::new(proc)),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::Prctl(proc) => Self {
                process_event: ProcessEventType::Prctl(ProcessPrctl::new(proc)),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::CreateUserNs => Self {
                process_event: ProcessEventType::CreateUserNs(ProcessCreateUserNs {}),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
            ProcessEventVariant::PtraceAccessCheck(proc) => Self {
                process_event: ProcessEventType::PtraceAccessCheck(ProcessPtraceAccessCheck::new(
                    proc,
                )),
                process,
                parent,
                timestamp: transmute_ktime(ktime),
            },
        }
    }
}

pub struct ProcessEventTransmuter;

#[async_trait]
impl Transmuter for ProcessEventTransmuter {
    async fn transmute(
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
                let high_level_event =
                    ProcessEvent::new(cached_process.process.clone(), parent, &msg.event, ktime);
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
