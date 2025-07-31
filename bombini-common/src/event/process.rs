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
    pub cap_inheritable: Capabilities,
    pub cap_permitted: Capabilities,
    pub cap_effective: Capabilities,
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
    pub effective: Capabilities,
    pub inheritable: Capabilities,
    pub permitted: Capabilities,
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

bitflags! {
    #[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct Capabilities: u64 {
        const CAP_CHOWN = 1 << 0;
        const CAP_DAC_OVERRIDE = 1 << 1;
        const CAP_DAC_READ_SEARCH = 1 << 2;
        const CAP_FOWNER = 1 << 3;
        const CAP_FSETID = 1 << 4;
        const CAP_KILL = 1 << 5;
        const CAP_SETGID = 1 << 6;
        const CAP_SETUID = 1 << 7;
        const CAP_SETPCAP = 1 << 8;
        const CAP_LINUX_IMMUTABLE = 1 << 9;
        const CAP_NET_BIND_SERVICE = 1 << 10;
        const CAP_NET_BROADCAST = 1 << 11;
        const CAP_NET_ADMIN = 1 << 12;
        const CAP_NET_RAW = 1 << 13;
        const CAP_IPC_LOCK = 1 << 14;
        const CAP_IPC_OWNER = 1 << 15;
        const CAP_SYS_MODULE = 1 << 16;
        const CAP_SYS_RAWIO = 1 << 17;
        const CAP_SYS_CHROOT = 1 << 18;
        const CAP_SYS_PTRACE = 1 << 19;
        const CAP_SYS_PACCT = 1 << 20;
        const CAP_SYS_ADMIN = 1 << 21;
        const CAP_SYS_BOOT = 1 << 22;
        const CAP_SYS_NICE = 1 << 23;
        const CAP_SYS_RESOURCE = 1 << 24;
        const CAP_SYS_TIME = 1 << 25;
        const CAP_SYS_TTY_CONFIG = 1 << 26;
        const CAP_MKNOD = 1 << 27;
        const CAP_LEASE = 1 << 28;
        const CAP_AUDIT_WRITE = 1 << 29;
        const CAP_AUDIT_CONTROL = 1 << 30;
        const CAP_SETFCAP = 1 << 31;
        const CAP_MAC_OVERRIDE = 1 << 32;
        const CAP_MAC_ADMIN = 1 << 33;
        const CAP_SYSLOG = 1 << 34;
        const CAP_WAKE_ALARM = 1 << 35;
        const CAP_BLOCK_SUSPEND = 1 << 36;
        const CAP_AUDIT_READ = 1 << 37;
        const CAP_PERFMON = 1 << 38;
        const CAP_BPF = 1 << 39;
        const CAP_CHECKPOINT_RESTORE = 1 << 40;

        const ALL_CAPS = Self::CAP_CHOWN.bits()
        | Self::CAP_DAC_OVERRIDE.bits()
        | Self::CAP_DAC_READ_SEARCH.bits()
        | Self::CAP_FOWNER.bits()
        | Self::CAP_FSETID.bits()
        | Self::CAP_KILL.bits()
        | Self::CAP_SETGID.bits()
        | Self::CAP_SETUID.bits()
        | Self::CAP_SETPCAP.bits()
        | Self::CAP_LINUX_IMMUTABLE.bits()
        | Self::CAP_NET_BIND_SERVICE.bits()
        | Self::CAP_NET_BROADCAST.bits()
        | Self::CAP_NET_ADMIN.bits()
        | Self::CAP_NET_RAW.bits()
        | Self::CAP_IPC_LOCK.bits()
        | Self::CAP_IPC_OWNER.bits()
        | Self::CAP_SYS_MODULE.bits()
        | Self::CAP_SYS_RAWIO.bits()
        | Self::CAP_SYS_CHROOT.bits()
        | Self::CAP_SYS_PTRACE.bits()
        | Self::CAP_SYS_PACCT.bits()
        | Self::CAP_SYS_ADMIN.bits()
        | Self::CAP_SYS_BOOT.bits()
        | Self::CAP_SYS_NICE.bits()
        | Self::CAP_SYS_RESOURCE.bits()
        | Self::CAP_SYS_TIME.bits()
        | Self::CAP_SYS_TTY_CONFIG.bits()
        | Self::CAP_MKNOD.bits()
        | Self::CAP_LEASE.bits()
        | Self::CAP_AUDIT_WRITE.bits()
        | Self::CAP_AUDIT_CONTROL.bits()
        | Self::CAP_SETFCAP.bits()
        | Self::CAP_MAC_OVERRIDE.bits()
        | Self::CAP_MAC_ADMIN.bits()
        | Self::CAP_SYSLOG.bits()
        | Self::CAP_WAKE_ALARM.bits()
        | Self::CAP_BLOCK_SUSPEND.bits()
        | Self::CAP_AUDIT_READ.bits()
        | Self::CAP_PERFMON.bits()
        | Self::CAP_BPF.bits()
        | Self::CAP_CHECKPOINT_RESTORE.bits();
    }
}
