//! Transmutes FileEvent to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::{
    Event,
    file::{AccessMode, CreationFlags, FileEventVariant, Imode},
};

use bitflags::bitflags;
use serde::{Serialize, Serializer};

use super::{
    Transmuter, cache::process::ProcessCache, process::Process, str_from_bytes, transmute_ktime,
};

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

#[derive(Clone, Debug)]
#[repr(transparent)]
struct ImodeEvent(Imode);

impl Serialize for ImodeEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut result = String::with_capacity(11);

        // Get file type
        let file_type = self.0 & Imode::S_IFMT;
        let file_type_char = match file_type {
            Imode::S_IFSOCK => 's',
            Imode::S_IFLNK => 'l',
            Imode::S_IFREG => '-',
            Imode::S_IFBLK => 'b',
            Imode::S_IFDIR => 'd',
            Imode::S_IFCHR => 'c',
            Imode::S_IFIFO => 'p',
            _ => '?',
        };
        result.push(file_type_char);

        // Access for owner
        result.push(if (self.0 & Imode::S_IRUSR).bits() != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (self.0 & Imode::S_IWUSR).bits() != 0 {
            'w'
        } else {
            '-'
        });

        let mut x = if (self.0 & Imode::S_IXUSR).bits() != 0 {
            'x'
        } else {
            '-'
        };
        if (self.0 & Imode::S_ISUID).bits() != 0 {
            x = if x == 'x' { 's' } else { 'S' };
        }
        result.push(x);

        // Access for group
        result.push(if (self.0 & Imode::S_IRGRP).bits() != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (self.0 & Imode::S_IWGRP).bits() != 0 {
            'w'
        } else {
            '-'
        });

        x = if (self.0 & Imode::S_IXGRP).bits() != 0 {
            'x'
        } else {
            '-'
        };
        if (self.0 & Imode::S_ISGID).bits() != 0 {
            x = if x == 'x' { 's' } else { 'S' };
        }
        result.push(x);

        // Access for others
        result.push(if (self.0 & Imode::S_IROTH).bits() != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (self.0 & Imode::S_IWOTH).bits() != 0 {
            'w'
        } else {
            '-'
        });

        x = if (self.0 & Imode::S_IXOTH).bits() != 0 {
            'x'
        } else {
            '-'
        };
        if (self.0 & Imode::S_ISVTX).bits() != 0 {
            x = if x == 'x' { 't' } else { 'T' };
        }
        result.push(x);

        serializer.serialize_str(&result)
    }
}

impl From<Imode> for ImodeEvent {
    fn from(value: Imode) -> Self {
        ImodeEvent(value)
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
    i_mode: ImodeEvent,
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
    i_mode: ImodeEvent,
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
    i_mode: ImodeEvent,
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
                    access_mode: info.access_mode,
                    creation_flags: info.creation_flags,
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

impl Transmuter for FileEventTransmuter {
    fn transmute(
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
