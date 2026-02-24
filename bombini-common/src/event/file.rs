//! File event module

use crate::constants::{MAX_FILE_PATH, MAX_FILENAME_SIZE};
use crate::event::process::ProcessKey;
use bitflags::bitflags;
#[cfg(feature = "user")]
use serde::Serialize;

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
    pub i_mode: Imode,
}

/// PathChmod info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PathChmod {
    /// full path
    pub path: [u8; MAX_FILE_PATH],
    /// i_mode
    pub i_mode: Imode,
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
    pub i_mode: Imode,
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

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct Imode: u16 {
        // File type
        const S_IFMT = 0o170000;
        const S_IFSOCK = 0o140000;
        const S_IFLNK = 0o120000;
        const S_IFREG = 0o100000;
        const S_IFBLK = 0o060000;
        const S_IFDIR = 0o040000;
        const S_IFCHR = 0o020000;
        const S_IFIFO = 0o010000;

        // Access type
        const S_ISUID = 0o4000;
        const S_ISGID = 0o2000;
        const S_ISVTX = 0o1000;

        const S_IRUSR = 0o0400;
        const S_IWUSR = 0o0200;
        const S_IXUSR = 0o0100;

        const S_IRGRP = 0o0040;
        const S_IWGRP = 0o0020;
        const S_IXGRP = 0o0010;

        const S_IROTH = 0o0004;
        const S_IWOTH = 0o0002;
        const S_IXOTH = 0o0001;
    }
}

#[cfg(feature = "user")]
impl core::str::FromStr for Imode {
    type Err = bitflags::parser::ParseError;

    fn from_str(imode_str: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(imode_str)
    }
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
