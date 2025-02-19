//! Transmutes Process to serializable struct

use bombini_common::event::process::ProcInfo;

use bitflags::bitflags;
use serde::Serialize;

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct ProcessEvent {
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

bitflags! {
    #[derive(Clone, Debug, Serialize)]
    #[repr(C)]
    pub struct SecureExec: u32 {
        const SETUID = 0b00000001;
        const SETGID = 0b00000010;
        const FILE_CAPS = 0b00000100;
    }
}

impl ProcessEvent {
    /// Constructs High level event representation from low eBPF
    pub fn new(proc: &mut ProcInfo) -> Self {
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
