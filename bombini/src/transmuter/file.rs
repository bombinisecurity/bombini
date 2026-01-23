//! Transmutes FileEvent to serialized format

use anyhow::anyhow;
use async_trait::async_trait;
use std::sync::Arc;

use bombini_common::event::{Event, file::FileEventVariant};

use bitflags::bitflags;
use serde::{Serialize, Serializer};

use super::{
    Transmuter, cache::process::ProcessCache, process::Process, str_from_bytes, transmute_ktime,
};

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
    pub struct ProtMode: u32 {
        const PROT_READ =   0b00000001;
        const PROT_WRITE =  0b00000010;
        const PROT_EXEC =   0b00000100;
    }
}

bitflags! {
    #[derive(Clone, Debug, Serialize)]
    #[repr(C)]
    pub struct SharingType: u32 {
        const MAP_SHARED     = 0x1;
        const MAP_PRIVATE    = 0x2;
        const MAP_DROPPABLAE = 0x8;
        const MAP_TYPE       = 0xf;
        const MAP_FIXED      = 0x10;
        const MAP_ANONYMOUS  = 0x20;
        const MAP_GROWSDOWN	 = 0x00100;
        const MAP_DENYWRITE  = 0x00800;
        const MAP_EXECUTABLE = 0x01000;
        const MAP_LOCKED     = 0x02000;
        const MAP_NORESERVE  = 0x04000;
        const MAP_POPULATE   = 0x08000;
        const MAP_NONBLOCK   = 0x10000;
        const MAP_STACK      = 0x20000;
        const MAP_HUGETLB    = 0x40000;
        const MAP_SYNC       = 0x80000;
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

/// File Event
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FileEvent {
    /// Process Information
    process: Arc<Process>,
    /// Parent Information
    parent: Option<Arc<Process>>,
    /// LSM File hook info
    hook: LsmFileHook,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FileOpenInfo {
    /// full path
    path: String,
    /// access mode passed to open()
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    access_mode: AccessMode,
    /// creation flags passed to open()
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    creation_flags: CreationFlags,
    /// File owner UID
    uid: u32,
    /// Group owner GID
    gid: u32,
    /// i_mode
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    i_mode: Imode,
}
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PathInfo {
    /// full path
    path: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PathSymlink {
    /// full path
    link_path: String,
    /// symlink target
    old_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChmodInfo {
    /// full path
    path: String,
    /// i_mode
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    i_mode: Imode,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChownInfo {
    /// full path
    path: String,
    /// UID
    uid: u32,
    /// GID
    gid: u32,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MountInfo {
    /// device name
    dev: String,
    /// mount path
    mnt: String,
    /// mount flags
    flags: u32,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MmapInfo {
    /// full path
    path: String,
    /// mmap protection
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    prot: ProtMode,
    /// mmap flags
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    flags: SharingType,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IoctlInfo {
    /// full path
    path: String,
    /// i_mode
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    i_mode: Imode,
    /// cmd
    cmd: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(u8)]
#[allow(dead_code)]
pub enum LsmFileHook {
    FileOpen(FileOpenInfo),
    PathTruncate(PathInfo),
    PathUnlink(PathInfo),
    PathSymlink(PathSymlink),
    PathChmod(ChmodInfo),
    PathChown(ChownInfo),
    SbMount(MountInfo),
    MmapFile(MmapInfo),
    FileIoctl(IoctlInfo),
}

impl FileEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        event: &FileEventVariant,
        ktime: u64,
    ) -> Self {
        match event {
            FileEventVariant::FileOpen(info) => {
                let info = FileOpenInfo {
                    path: str_from_bytes(&info.path),
                    access_mode: AccessMode::from_bits_truncate(1 << (info.flags & 3)),
                    creation_flags: CreationFlags::from_bits_truncate(info.flags),
                    uid: info.uid,
                    gid: info.gid,
                    i_mode: info.i_mode.into(),
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::FileOpen(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::PathTruncate(path) => {
                let info = PathInfo {
                    path: str_from_bytes(path),
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::PathTruncate(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::PathUnlink(path) => {
                let path = str_from_bytes(path);
                let info = PathInfo { path };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::PathUnlink(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::PathSymlink(info) => {
                let info = PathSymlink {
                    link_path: str_from_bytes(&info.link_path),
                    old_path: str_from_bytes(&info.old_path),
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::PathSymlink(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::PathChmod(info) => {
                let info = ChmodInfo {
                    path: str_from_bytes(&info.path),
                    i_mode: info.i_mode.into(),
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::PathChmod(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::PathChown(info) => {
                let info = ChownInfo {
                    path: str_from_bytes(&info.path),
                    uid: info.uid,
                    gid: info.gid,
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::PathChown(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::SbMount(info) => {
                let info = MountInfo {
                    dev: str_from_bytes(&info.name),
                    mnt: str_from_bytes(&info.path),
                    flags: info.flags,
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::SbMount(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::MmapFile(info) => {
                let info = MmapInfo {
                    path: str_from_bytes(&info.path),
                    prot: ProtMode::from_bits_truncate(info.prot),
                    flags: SharingType::from_bits_truncate(info.flags),
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::MmapFile(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
            FileEventVariant::FileIoctl(info) => {
                let info = IoctlInfo {
                    path: str_from_bytes(&info.path),
                    i_mode: info.i_mode.into(),
                    cmd: info.cmd,
                };
                Self {
                    process,
                    parent,
                    hook: LsmFileHook::FileIoctl(info),
                    timestamp: transmute_ktime(ktime),
                }
            }
        }
    }
}

pub struct FileEventTransmuter;

#[async_trait]
impl Transmuter for FileEventTransmuter {
    async fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::File(msg) = event {
            let parent = if let Some(cached_process) = process_cache.get(&msg.parent) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "FileEvent: No parent Process record (pid: {}, start: {}) found in cache",
                    msg.parent.pid,
                    transmute_ktime(msg.parent.start)
                );
                None
            };
            if let Some(cached_process) = process_cache.get_mut(&msg.process) {
                let high_level_event =
                    FileEvent::new(cached_process.process.clone(), parent, &msg.event, ktime);
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "FileEvent: No process (pid: {}, start: {}) found in cache",
                    msg.process.pid,
                    transmute_ktime(msg.process.start),
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::FileEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_gtfobins_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&event_ref)
            .unwrap();
        let _ = writeln!(file, "## FileMon\n\n```json");
        let schema = schemars::schema_for!(FileEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
