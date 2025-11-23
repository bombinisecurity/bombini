//! Transmutes Process to serializable struct

use anyhow::anyhow;
use async_trait::async_trait;

use bombini_common::event::{
    Event,
    process::{
        Capabilities, Cgroup, ImaHash, LsmSetUidFlags, PrctlCmd, ProcCapset, ProcInfo, ProcPrctl,
        ProcPtraceAccessCheck, ProcSetUid, ProcessMsg, PtraceMode, SecureExec,
    },
};

use serde::{Serialize, Serializer};

use super::{Transmuter, str_from_bytes, transmute_ktime};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessExec {
    /// Process Infro
    process: Process,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessExit {
    /// Process Infro
    process: Process,
    /// Event's date and time
    timestamp: String,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct Process {
    /// Exec start
    pub start_time: String,
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
    pub cap_inheritable: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub cap_permitted: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub cap_effective: Capabilities,
    pub secureexec: SecureExec,
    /// executable name
    pub filename: String,
    /// full binary path
    pub binary_path: String,
    /// current work directory
    pub args: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    /// skip for host
    pub container_id: String,
    /// IMA binary hash
    #[serde(skip_serializing_if = "is_invalid_ima")]
    #[serde(serialize_with = "serialize_ima")]
    pub binary_ima_hash: ImaHash,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct ProcessSetUid {
    euid: u32,
    uid: u32,
    fsuid: u32,
    /// LSM_SETID_* flag values
    flags: LsmSetUidFlags,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct ProcessCapset {
    #[serde(serialize_with = "serialize_capabilities")]
    pub inheritable: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub permitted: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub effective: Capabilities,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct ProcessPrctl {
    cmd: PrctlCmdUser,
}

/// Enumeration of prctl supported commands
#[derive(Clone, Debug, Serialize)]
#[repr(u8)]
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

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct ProcessCreateUserNs {}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
pub struct ProcessPtraceAccessCheck {
    child: Process,
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
    pub fn new(event: &ProcInfo, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event),
        }
    }
}

pub struct ProcessExecTransmuter;

#[async_trait]
impl Transmuter for ProcessExecTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcExec(event) = event {
            let high_level_event = ProcessExec::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

impl ProcessExit {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &ProcInfo, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event),
        }
    }
}

pub struct ProcessExitTransmuter;

#[async_trait]
impl Transmuter for ProcessExitTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::ProcExit(event) = event {
            let high_level_event = ProcessExit::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
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

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessEvent {
    /// Process Infro
    process: Process,
    /// Process event
    process_event: ProcessEventType,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[allow(clippy::large_enum_variant)]
pub enum ProcessEventType {
    Setuid(ProcessSetUid),
    Setcaps(ProcessCapset),
    Prctl(ProcessPrctl),
    CreateUserNs(ProcessCreateUserNs),
    PtraceAccessCheck(ProcessPtraceAccessCheck),
}

impl ProcessEvent {
    pub fn new(event: &ProcessMsg, ktime: u64) -> Self {
        match event {
            ProcessMsg::Setuid(proc) => Self {
                process_event: ProcessEventType::Setuid(ProcessSetUid::new(proc)),
                process: Process::new(&proc.process),
                timestamp: transmute_ktime(ktime),
            },
            ProcessMsg::Setcaps(proc) => Self {
                process_event: ProcessEventType::Setcaps(ProcessCapset::new(proc)),
                process: Process::new(&proc.process),
                timestamp: transmute_ktime(ktime),
            },
            ProcessMsg::Prctl(proc) => Self {
                process_event: ProcessEventType::Prctl(ProcessPrctl::new(proc)),
                process: Process::new(&proc.process),
                timestamp: transmute_ktime(ktime),
            },
            ProcessMsg::CreateUserNs(proc) => Self {
                process_event: ProcessEventType::CreateUserNs(ProcessCreateUserNs {}),
                process: Process::new(&proc.process),
                timestamp: transmute_ktime(ktime),
            },
            ProcessMsg::PtraceAccessCheck(proc) => Self {
                process_event: ProcessEventType::PtraceAccessCheck(ProcessPtraceAccessCheck::new(
                    proc,
                )),
                process: Process::new(&proc.process),
                timestamp: transmute_ktime(ktime),
            },
        }
    }
}

pub struct ProcessEventTransmuter;

#[async_trait]
impl Transmuter for ProcessEventTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::Process(event) = event {
            let high_level_event = ProcessEvent::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}
