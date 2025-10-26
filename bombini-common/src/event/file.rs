//! File event module

use crate::constants::{MAX_FILE_PATH, MAX_FILENAME_SIZE};
use crate::event::process::ProcInfo;

/// File open/mmap, etc. event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileMsg {
    pub process: ProcInfo,
    pub hook: u8,
    /// full path or full dir path for unlink
    /// or mount path
    pub path: [u8; MAX_FILE_PATH],
    /// file/device name
    pub name: [u8; MAX_FILENAME_SIZE],
    /// flags passed to open()
    /// or mount flags from sb_mount()
    /// mmap flags, or ioctl cmd
    pub flags: u32,
    /// mmap protection falgs
    pub prot: u32,
    /// File owner UID
    pub uid: u32,
    /// Group owner GID
    pub gid: u32,
    /// i_mode
    pub i_mode: u16,
}

pub const HOOK_FILE_OPEN: u8 = 0;

pub const HOOK_PATH_TRUNCATE: u8 = 1;

pub const HOOK_PATH_UNLINK: u8 = 2;

pub const HOOK_PATH_CHMOD: u8 = 3;

pub const HOOK_PATH_CHOWN: u8 = 4;

pub const HOOK_SB_MOUNT: u8 = 5;

pub const HOOK_MMAP_FILE: u8 = 6;

pub const HOOK_FILE_IOCTL: u8 = 7;
