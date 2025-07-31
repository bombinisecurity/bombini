//! Process event module

use bitflags::bitflags;

#[cfg(feature = "user")]
use serde::Serialize;

use crate::constants::{DOCKER_ID_LENGTH, MAX_ARGS_SIZE, MAX_FILENAME_SIZE, MAX_FILE_PATH};

/// Process event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcInfo {
    /// PID
    pub pid: u32,
    /// TID
    pub tid: u32,
    /// Parent PID
    pub ppid: u32,
    /// Task Creds
    pub creds: Cred,
    /// login UID
    pub auid: u32,
    /// if this event from clone
    pub clonned: bool,
    /// executable name
    pub filename: [u8; MAX_FILENAME_SIZE],
    /// full binary path
    pub binary_path: [u8; MAX_FILE_PATH],
    /// command line arguments without argv[0]
    pub args: [u8; MAX_ARGS_SIZE],
    /// Cgroup info
    pub cgroup: Cgroup,
}

/// Creds
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Cred {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub secureexec: SecureExec,
}

/// Cgroup info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Cgroup {
    pub cgroup_id: u64,
    pub cgroup_name: [u8; DOCKER_ID_LENGTH],
}

bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct SecureExec: u32 {
        const SETUID = 0b00000001;
        const SETGID = 0b00000010;
        const FILE_CAPS = 0b00000100;
    }
}

/// Set UID info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcSetUid {
    pub process: ProcInfo,
    pub euid: u32,
    pub uid: u32,
    pub fsuid: u32,
    pub flags: LsmSetUidFlags,
}

/// Capset info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcCapset {
    pub process: ProcInfo,
    pub effective: u64,
    pub inheritable: u64,
    pub permitted: u64,
}

bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct LsmSetUidFlags: u32 {
        const LSM_SETID_ID = 0b00000001;
        const LSM_SETID_RE = 0b00000010;
        const LSM_SETID_RES = 0b00000100;
        const LSM_SETID_FS = 0b00001000;
    }
}
