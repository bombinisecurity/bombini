//! File event module

use crate::constants::{MAX_FILE_PATH, MAX_FILENAME_SIZE};
use crate::event::process::ProcessKey;

/// File open/mmap, etc. event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    pub event: FileEventVariant,
}

/// FileOpen info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileOpen {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// flags passed to open()
    pub flags: u32,
    /// File owner UID
    pub uid: u32,
    /// Group owner GID
    pub gid: u32,
    /// i_mode
    pub i_mode: u16,
}

/// PathChmod info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PathChmod {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// i_mode
    pub i_mode: u16,
}

/// PathChown info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PathChown {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// File owner UID
    pub uid: u32,
    /// Group owner GID
    pub gid: u32,
}

/// SbMount info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SbMount {
    /// full mnt path
    pub path: [u8; MAX_FILE_PATH],
    pub flags: u32,
    /// device name
    pub name: [u8; MAX_FILENAME_SIZE],
}

/// Mmap info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct MmapFile {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// mmap flags
    pub flags: u32,
    /// protection flags
    pub prot: u32,
}

/// FileIoctl info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileIoctl {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// ioctl cmd
    pub cmd: u32,
    /// i_mode
    pub i_mode: u16,
}

/// Raw File event messages
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum FileEventVariant {
    FileOpen(FileOpen) = 0,
    PathTruncate([u8; MAX_FILE_PATH]) = 1,
    PathUnlink([u8; MAX_FILE_PATH]) = 2,
    PathChmod(PathChmod) = 3,
    PathChown(PathChown) = 4,
    SbMount(SbMount) = 5,
    MmapFile(MmapFile) = 6,
    FileIoctl(FileIoctl) = 7,
}
