//! Transmutes Process to serializable struct

use bombini_common::event::process::{ProcInfo, SecureExec};

use serde::Serialize;

use super::Transmute;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessExec {
    /// Process Infro
    process: Process,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessExit {
    /// Process Infro
    process: Process,
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
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub secureexec: SecureExec,
    /// executable name
    pub filename: String,
    /// full binary path
    pub binary_path: String,
    /// current work directory
    pub args: String,
}

impl Process {
    /// Constructs High level event representation from low eBPF
    pub fn new(mut proc: ProcInfo) -> Self {
        let filename = if *proc.filename.last().unwrap() == 0x0 {
            let zero = proc.filename.iter().position(|e| *e == 0x0).unwrap();
            String::from_utf8_lossy(&proc.filename[..zero]).to_string()
        } else {
            String::from_utf8_lossy(&proc.filename).to_string()
        };

        let binary_path = if *proc.binary_path.last().unwrap() == 0x0 {
            let zero = proc.binary_path.iter().position(|e| *e == 0x0).unwrap();
            String::from_utf8_lossy(&proc.binary_path[..zero]).to_string()
        } else {
            String::from_utf8_lossy(&proc.binary_path).to_string()
        };

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
            filename,
            binary_path,
            args,
        }
    }
}

impl ProcessExec {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcInfo) -> Self {
        Self {
            process: Process::new(event),
        }
    }
}

impl Transmute for ProcessExec {}

impl ProcessExit {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: ProcInfo) -> Self {
        Self {
            process: Process::new(event),
        }
    }
}

impl Transmute for ProcessExit {}
