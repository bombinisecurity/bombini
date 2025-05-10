//! Transmutes FileEvent to serialized format

use bombini_common::event::file::{FileMsg, HOOK_FILE_OPEN, HOOK_PATH_TRUNCATE, HOOK_PATH_UNLINK};

use bitflags::bitflags;
use serde::{Serialize, Serializer};

use super::process::Process;
use super::Transmute;

bitflags! {
    #[derive(Clone, Debug, Serialize)]
    #[repr(C)]
    pub struct AccessMode: u32 {
        const O_RDONLY =    0b00000001;
        const O_WRONLY =    0b00000010;
        const O_RDWR =      0b00000100;
    }
}

bitflags! {
    #[derive(Clone, Debug, Serialize)]
    #[repr(C)]
    pub struct CreationFlags: u32 {
        const O_CREAT =	    0o00000100;
        const O_EXCL =      0o00000200;
        const O_NOCTTY =    0o00000400;
        const O_TRUNC =	    0o00001000;
        const O_APPEND =    0o00002000;
        const O_NONBLOCK =  0o00004000;
        const O_DSYNC =	    0o00010000;
        const O_FASYNC =    0o00020000;
        const O_DIRECT	=   0o00040000;
        const O_LARGEFILE = 0o00100000;
        const O_DIRECTORY =	0o00200000;
        const O_NOFOLLOW =	0o00400000;
        const O_NOATIME	=   0o01000000;
        const O_CLOEXEC =   0o02000000;
        const O_SYNC =	    0o04010000;
        const O_PATH =		0o10000000;
        const O_TMPFILE =   0o20200000;
    }
}

#[derive(Clone, Debug)]
struct Imode(u16);

// File type
const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;
const S_IFLNK: u16 = 0o120000;
const S_IFREG: u16 = 0o100000;
const S_IFBLK: u16 = 0o060000;
const S_IFDIR: u16 = 0o040000;
const S_IFCHR: u16 = 0o020000;
const S_IFIFO: u16 = 0o010000;

// Access type
const S_ISUID: u16 = 0o4000;
const S_ISGID: u16 = 0o2000;
const S_ISVTX: u16 = 0o1000;

const S_IRUSR: u16 = 0o0400;
const S_IWUSR: u16 = 0o0200;
const S_IXUSR: u16 = 0o0100;

const S_IRGRP: u16 = 0o0040;
const S_IWGRP: u16 = 0o0020;
const S_IXGRP: u16 = 0o0010;

const S_IROTH: u16 = 0o0004;
const S_IWOTH: u16 = 0o0002;
const S_IXOTH: u16 = 0o0001;

impl Serialize for Imode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut result = String::with_capacity(11);

        // Get file type
        let file_type = self.0 & S_IFMT;
        let file_type_char = match file_type {
            S_IFSOCK => 's',
            S_IFLNK => 'l',
            S_IFREG => '-',
            S_IFBLK => 'b',
            S_IFDIR => 'd',
            S_IFCHR => 'c',
            S_IFIFO => 'p',
            _ => '?',
        };
        result.push(file_type_char);

        // Access for owner
        result.push(if (self.0 & S_IRUSR) != 0 { 'r' } else { '-' });
        result.push(if (self.0 & S_IWUSR) != 0 { 'w' } else { '-' });

        let mut x = if (self.0 & S_IXUSR) != 0 { 'x' } else { '-' };
        if (self.0 & S_ISUID) != 0 {
            x = if x == 'x' { 's' } else { 'S' };
        }
        result.push(x);

        // Access for group
        result.push(if (self.0 & S_IRGRP) != 0 { 'r' } else { '-' });
        result.push(if (self.0 & S_IWGRP) != 0 { 'w' } else { '-' });

        x = if (self.0 & S_IXGRP) != 0 { 'x' } else { '-' };
        if (self.0 & S_ISGID) != 0 {
            x = if x == 'x' { 's' } else { 'S' };
        }
        result.push(x);

        // Access for others
        result.push(if (self.0 & S_IROTH) != 0 { 'r' } else { '-' });
        result.push(if (self.0 & S_IWOTH) != 0 { 'w' } else { '-' });

        x = if (self.0 & S_IXOTH) != 0 { 'x' } else { '-' };
        if (self.0 & S_ISVTX) != 0 {
            x = if x == 'x' { 't' } else { 'T' };
        }
        result.push(x);

        serializer.serialize_str(&result)
    }
}

impl From<u16> for Imode {
    fn from(value: u16) -> Self {
        Imode(value)
    }
}

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct FileEvent {
    /// Process Infro
    process: Process,
    /// LSM File hook info
    hook: LsmFileHook,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileOpenInfo {
    /// full path
    path: String,
    /// access mode passed to open()
    access_mode: AccessMode,
    /// creation flags passed to open()
    creation_flags: CreationFlags,
    /// File owner UID
    uid: u32,
    /// Group owner GID
    gid: u32,
    /// i_mode
    i_mode: Imode,
}
#[derive(Clone, Debug, Serialize)]
pub struct PathTruncateInfo {
    /// full path
    path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathUnlinkInfo {
    /// full directory path
    dir: String,
    /// file name
    filename: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[allow(dead_code)]
pub enum LsmFileHook {
    FileOpen(FileOpenInfo),
    PathTruncate(PathTruncateInfo),
    PathUnlink(PathUnlinkInfo),
}

impl FileEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: FileMsg) -> Self {
        match event.hook {
            HOOK_FILE_OPEN => {
                let info = FileOpenInfo {
                    path: str_from_bytes(&event.path),
                    access_mode: AccessMode::from_bits_truncate(1 << (event.flags & 3)),
                    creation_flags: CreationFlags::from_bits_truncate(event.flags),
                    uid: event.uid,
                    gid: event.gid,
                    i_mode: event.i_mode.into(),
                };
                Self {
                    process: Process::new(event.process),
                    hook: LsmFileHook::FileOpen(info),
                }
            }
            HOOK_PATH_TRUNCATE => {
                let info = PathTruncateInfo {
                    path: str_from_bytes(&event.path),
                };
                Self {
                    process: Process::new(event.process),
                    hook: LsmFileHook::PathTruncate(info),
                }
            }
            HOOK_PATH_UNLINK => {
                let info = PathUnlinkInfo {
                    dir: str_from_bytes(&event.path),
                    filename: str_from_bytes(&event.name),
                };
                Self {
                    process: Process::new(event.process),
                    hook: LsmFileHook::PathUnlink(info),
                }
            }
            _ => {
                panic!("unsupported LSM BPF File hook");
            }
        }
    }
}

fn str_from_bytes(bytes: &[u8]) -> String {
    if *bytes.last().unwrap() == 0x0 {
        let zero = bytes.iter().position(|e| *e == 0x0).unwrap();
        String::from_utf8_lossy(&bytes[..zero]).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

impl Transmute for FileEvent {}
