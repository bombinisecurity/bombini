//! Process event module

use bitflags::bitflags;

#[cfg(feature = "user")]
use procfs::process::Process;
#[cfg(feature = "user")]
use serde::Serialize;

use crate::constants::{
    DOCKER_ID_LENGTH, MAX_ARGS_SIZE, MAX_FILE_PATH, MAX_FILENAME_SIZE, MAX_IMA_HASH_SIZE,
};

/// Process information
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct ProcInfo {
    /// exec time
    pub start: u64,
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
    /// IMA binary hash
    pub ima_hash: ImaHash,
    /// internal for gc clean up
    pub exited: bool,
}

#[cfg(feature = "user")]
impl ProcInfo {
    pub fn from_procfs(process: &Process) -> Option<ProcInfo> {
        let Ok(status) = process.status() else {
            return None;
        };
        if status.pid != status.tgid {
            // Use only for thread leaders
            return None;
        }
        let creds = Cred {
            uid: status.ruid,
            euid: status.euid,
            gid: status.rgid,
            egid: status.egid,
            cap_effective: Capabilities::from_bits_truncate(status.capeff),
            cap_permitted: Capabilities::from_bits_truncate(status.capprm),
            cap_inheritable: Capabilities::from_bits_truncate(status.capinh),
            secureexec: SecureExec::from_bits_truncate(0),
        };
        let mut binary_path = [0u8; MAX_FILE_PATH];
        let mut filename = [0u8; MAX_FILENAME_SIZE];
        let mut args = [0u8; MAX_ARGS_SIZE];
        let mut cgroup_name = [0u8; DOCKER_ID_LENGTH];
        let Ok(auid) = process.loginuid() else {
            return None;
        };
        if let Ok(exe) = process.exe() {
            let k_str = exe.to_str().unwrap().as_bytes();
            let len = k_str.len();
            if len < MAX_FILE_PATH {
                binary_path[..len].clone_from_slice(k_str);
            } else {
                binary_path.clone_from_slice(&k_str[..MAX_FILE_PATH]);
            }
            let k_str = exe.file_name().unwrap().as_encoded_bytes();
            let len = k_str.len();
            if len < MAX_FILENAME_SIZE {
                filename[..len].clone_from_slice(k_str);
            } else {
                filename.clone_from_slice(&k_str[..MAX_FILENAME_SIZE]);
            }
        }

        if let Ok(cmdline) = process.cmdline() {
            let mut index = 0;
            for arg in cmdline.iter().skip(1) {
                let arg_bytes = arg.as_bytes();
                if index + arg_bytes.len() + 1 > MAX_ARGS_SIZE {
                    break;
                }
                args[index..index + arg_bytes.len()].copy_from_slice(arg_bytes);
                index += arg_bytes.len();
                args[index] = 0;
                index += 1;
            }
        }

        let Ok(cgroups) = process.cgroups() else {
            return None;
        };
        let k_str = cgroups.0[0].pathname.as_bytes();
        let len = k_str.len();
        if len < DOCKER_ID_LENGTH {
            cgroup_name[..len].clone_from_slice(k_str);
        } else {
            cgroup_name.clone_from_slice(&k_str[..DOCKER_ID_LENGTH]);
        }

        let cgroup = Cgroup {
            cgroup_id: 0,
            cgroup_name,
        };
        let ima_stub = ImaHash {
            algo: 0,
            hash: [0u8; MAX_IMA_HASH_SIZE],
        };
        let Ok(stats) = process.stat() else {
            return None;
        };

        Some(Self {
            // The time the process started after system boot.
            // In kernels before Linux 2.6, this value was expressed in jiffies.
            // Since Linux 2.6, the value is expressed in clock ticks (divide by sysconf(_SC_CLK_TCK)).
            // CLK_TCK is 100. Convert to nanoseconds.
            start: stats.starttime * 1_000_000_000 / 100,
            tid: status.pid as u32,
            pid: status.tgid as u32,
            ppid: status.ppid as u32,
            creds,
            auid,
            clonned: false,
            exited: false,
            filename,
            binary_path,
            args,
            cgroup,
            ima_hash: ima_stub,
        })
    }
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for ProcInfo {}
}

/// Creds
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct Cred {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub cap_inheritable: Capabilities,
    pub cap_permitted: Capabilities,
    pub cap_effective: Capabilities,
    pub secureexec: SecureExec,
}

/// Cgroup info
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct Cgroup {
    pub cgroup_id: u64,
    pub cgroup_name: [u8; DOCKER_ID_LENGTH],
}

bitflags! {
    #[derive(Clone, Debug, PartialEq, Copy)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    /// extend AT_SECURE logic from https://man7.org/linux/man-pages/man3/getauxval.3.html
    /// with more fields
    pub struct SecureExec: u32 {
        const SETUID = 0b00000001;
        const SETGID = 0b00000010;
        const FILE_CAPS = 0b00000100;
        const FILELESS_EXEC = 0b00001000;
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

/// IMA file hash
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct ImaHash {
    pub algo: i8,
    pub hash: [u8; MAX_IMA_HASH_SIZE],
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
    #[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
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

#[cfg(feature = "user")]
impl core::str::FromStr for Capabilities {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags_str: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(flags_str)
    }
}

/// Enumeration of prctl supported commands
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum PrctlCmd {
    Opcode(u8) = 0,
    PrSetDumpable(u8) = 4,
    PrSetKeepCaps(u8) = 8,
    PrSetName { name: [u8; 16] } = 15,
    PrSetSecurebits(u32) = 28,
}

pub const PR_SET_DUMPABLE: u8 = 4;
pub const PR_SET_KEEPCAPS: u8 = 8;
pub const PR_SET_NAME: u8 = 15;
pub const PR_SET_SECUREBITS: u8 = 28;

/// Prctl info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcPrctl {
    pub process: ProcInfo,
    pub cmd: PrctlCmd,
}

/// create_user_ns info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcCreateUserNs {
    pub process: ProcInfo,
}

/// ptrace_attach info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcPtraceAccessCheck {
    pub process: ProcInfo,
    pub child: ProcInfo,
    pub mode: PtraceMode,
}

bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct PtraceMode: u32 {
        const PTRACE_MODE_READ = 0b00000001;
        const PTRACE_MODE_ATTACH = 0b00000010;
        const PTRACE_MODE_NOAUDIT = 0b00000100;
        const PTRACE_MODE_FSCRED = 0b00001000;
        const PTRACE_MODE_REALCREDS = 0b00010000;
    }
}

/// Raw Process event messages
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum ProcessMsg {
    /// Set uid/euid for process
    Setuid(ProcSetUid) = 0,
    /// Set capabilities for process
    Setcaps(ProcCapset) = 1,
    /// Prctl cmd for process
    Prctl(ProcPrctl) = 2,
    /// Create user namespace
    CreateUserNs(ProcCreateUserNs) = 3,
    /// Ptrace access check
    PtraceAccessCheck(ProcPtraceAccessCheck) = 4,
}
