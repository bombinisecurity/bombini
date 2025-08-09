//! Transmutes Process to serializable struct

use bombini_common::event::process::{
    Capabilities, LsmSetUidFlags, PrctlCmd, ProcCapset, ProcCreateUserNs, ProcInfo, ProcPrctl,
    ProcPtraceAccessCheck, ProcSetUid, PtraceMode, SecureExec,
};

use serde::{Serialize, Serializer};

use super::{str_from_bytes, transmute_ktime, Transmute};

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
    /// cgroup name
    pub cgroup_name: String,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessSetUid {
    /// Process Infro
    process: Process,
    euid: u32,
    uid: u32,
    fsuid: u32,
    /// LSM_SETID_* flag values
    flags: LsmSetUidFlags,
    /// Event's date and time
    timestamp: String,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessCapset {
    /// Process Infro
    process: Process,
    #[serde(serialize_with = "serialize_capabilities")]
    pub inheritable: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub permitted: Capabilities,
    #[serde(serialize_with = "serialize_capabilities")]
    pub effective: Capabilities,
    /// Event's date and time
    timestamp: String,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessPrctl {
    /// Process Infro
    process: Process,
    cmd: PrctlCmdUser,
    timestamp: String,
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

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessCreateUserNs {
    /// Process Infro
    process: Process,
    timestamp: String,
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessPtraceAccessCheck {
    /// Process Infro
    process: Process,
    child: Process,
    mode: PtraceMode,
    timestamp: String,
}

impl Process {
    /// Constructs High level event representation from low eBPF
    pub fn new(mut proc: ProcInfo) -> Self {
        proc.args.iter_mut().for_each(|e| {
            if *e == 0x00 {
                *e = 0x20
            }
        });
        let args = String::from_utf8_lossy(&proc.args).trim_end().to_string();
        Self {
            pid: proc.pid,
            tid: proc.tid,
            ppid: proc.ppid,
            auid: proc.auid,
            uid: proc.creds.uid,
            euid: proc.creds.euid,
            cap_effective: proc.creds.cap_effective,
            cap_permitted: proc.creds.cap_permitted,
            cap_inheritable: proc.creds.cap_inheritable,
            secureexec: SecureExec::from_bits_truncate(proc.creds.secureexec.bits()),
            filename: str_from_bytes(&proc.filename),
            binary_path: str_from_bytes(&proc.binary_path),
            args,
            cgroup_name: str_from_bytes(&proc.cgroup.cgroup_name),
        }
    }
}

impl ProcessExec {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcInfo, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event),
        }
    }
}

impl Transmute for ProcessExec {}

impl ProcessExit {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcInfo, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event),
        }
    }
}

impl Transmute for ProcessExit {}

impl ProcessSetUid {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcSetUid, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            uid: event.uid,
            euid: event.euid,
            fsuid: event.fsuid,
            flags: event.flags,
            process: Process::new(event.process),
        }
    }
}

impl Transmute for ProcessSetUid {}

impl ProcessCapset {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcCapset, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            effective: event.effective,
            inheritable: event.inheritable,
            permitted: event.permitted,
            process: Process::new(event.process),
        }
    }
}

impl Transmute for ProcessCapset {}

impl ProcessPrctl {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcPrctl, ktime: u64) -> Self {
        let cmd = match event.cmd {
            PrctlCmd::Opcode(op) => PrctlCmdUser::Opcode(op),
            PrctlCmd::PrSetDumpable(v) => PrctlCmdUser::PrSetDumpable(v),
            PrctlCmd::PrSetKeepCaps(v) => PrctlCmdUser::PrSetKeepCaps(v),
            PrctlCmd::PrSetSecurebits(v) => PrctlCmdUser::PrSetSecurebits(v),
            PrctlCmd::PrSetName { name } => PrctlCmdUser::PrSetName {
                name: str_from_bytes(&name),
            },
        };
        Self {
            timestamp: transmute_ktime(ktime),
            cmd,
            process: Process::new(event.process),
        }
    }
}

impl Transmute for ProcessPrctl {}

impl ProcessCreateUserNs {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcCreateUserNs, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event.process),
        }
    }
}

impl Transmute for ProcessCreateUserNs {}

impl ProcessPtraceAccessCheck {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcPtraceAccessCheck, ktime: u64) -> Self {
        Self {
            timestamp: transmute_ktime(ktime),
            process: Process::new(event.process),
            child: Process::new(event.child),
            mode: event.mode,
        }
    }
}

impl Transmute for ProcessPtraceAccessCheck {}
