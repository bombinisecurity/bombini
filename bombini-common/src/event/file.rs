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

/// FileIoctl info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PathSymlink {
    /// path to symlink
    pub link_path: [u8; MAX_FILE_PATH],
    /// path to target
    pub old_path: [u8; MAX_FILE_PATH],
}

/// Raw File event messages
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum FileEventVariant {
    FileOpen(FileOpen) = FileEventNumber::FileOpen as u8,
    PathTruncate([u8; MAX_FILE_PATH]) = FileEventNumber::PathTruncate as u8,
    PathUnlink([u8; MAX_FILE_PATH]) = FileEventNumber::PathUnlink as u8,
    PathSymlink(PathSymlink) = FileEventNumber::PathSymlink as u8,
    PathChmod(PathChmod) = FileEventNumber::PathChmod as u8,
    PathChown(PathChown) = FileEventNumber::PathChown as u8,
    SbMount(SbMount) = FileEventNumber::SbMount as u8,
    MmapFile(MmapFile) = FileEventNumber::MmapFile as u8,
    FileIoctl(FileIoctl) = FileEventNumber::FileIoctl as u8,
}

#[repr(C)]
pub enum FileEventNumber {
    FileOpen,
    PathTruncate,
    PathUnlink,
    PathSymlink,
    PathChmod,
    PathChown,
    SbMount,
    MmapFile,
    FileIoctl,

    TotalFileEvents,
}
