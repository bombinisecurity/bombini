//! File event module

use crate::event::process::{ProcInfo, MAX_FILENAME_SIZE, MAX_FILE_PATH};

/// File open/mmap, etc. event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileMsg {
    pub process: ProcInfo,
    pub hook: u8,
    /// full path or full dir path for unlink
    pub path: [u8; MAX_FILE_PATH],
    /// file name
    pub name: [u8; MAX_FILENAME_SIZE],
    /// flags passed to open()
    pub flags: u32,
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
