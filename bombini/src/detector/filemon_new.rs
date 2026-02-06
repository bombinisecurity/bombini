use std::{collections::HashMap, path::Path, sync::Arc};

use crate::detector::{Detector, Version};
use aya::maps::MapError;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use crate::proto::config::{FileMonNewConfig, Rule};
use crate::rule::serializer::{SerializedRules, filemon::FileOpenPredicate};

pub struct FileMonNew {
    ebpf: Ebpf,
    hooks: Vec<HookData>,
}

struct HookData {
    hook: FileMonHook,
    serialized_rules: SerializedRules<FileOpenPredicate>,

    map_sizes: HashMap<String, u32>,
}

#[derive(Debug, Copy, Clone)]
enum FileMonHook {
    FileOpen,
    PathTruncate,
    PathUnlink,
    PathSymlink,
    PathChmod,
    PathChown,
    SbMount,
    MmapFile,
    FileIoctl,
}

impl FileMonHook {
    fn map_prefix(&self) -> &'static str {
        match self {
            FileMonHook::FileOpen => "FILEMON_FILE_OPEN",
            FileMonHook::PathTruncate => "FILEMON_PATH_TRUNCATE",
            FileMonHook::PathUnlink => "FILEMON_PATH_UNLINK",
            FileMonHook::PathSymlink => "FILEMON_PATH_SYMLINK",
            FileMonHook::PathChmod => "FILEMON_PATH_CHMOD",
            FileMonHook::PathChown => "FILEMON_PATH_CHOWN",
            FileMonHook::SbMount => "FILEMON_SB_MOUNT",
            FileMonHook::MmapFile => "FILEMON_MMAP_FILE",
            FileMonHook::FileIoctl => "FILEMON_FILE_IOCTL",
        }
    }
}

impl HookData {
    fn new(hook: FileMonHook, rules: &[Rule]) -> Result<Self, anyhow::Error> {
        let mut serialized_rules = SerializedRules::new();
        serialized_rules.serialize_rules(rules)?;
        let map_sizes = serialized_rules.map_sizes(hook.map_prefix());

        Ok(HookData {
            hook,
            serialized_rules,
            map_sizes,
        })
    }
}

impl FileMonNew {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        config: Arc<FileMonNewConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.map_pin_path(maps_pin_path.as_ref());

        let mut hooks = Vec::new();
        if let Some(file_open) = &config.file_open
            && file_open.enabled
        {
            hooks.push(HookData::new(FileMonHook::FileOpen, &file_open.rules)?);
        }
        if let Some(path_truncate) = &config.path_truncate
            && path_truncate.enabled
        {
            hooks.push(HookData::new(
                FileMonHook::PathTruncate,
                &path_truncate.rules,
            )?);
        }
        if let Some(path_unlink) = &config.path_unlink
            && path_unlink.enabled
        {
            hooks.push(HookData::new(FileMonHook::PathUnlink, &path_unlink.rules)?);
        }
        if let Some(path_symlink) = &config.path_symlink
            && path_symlink.enabled
        {
            hooks.push(HookData::new(
                FileMonHook::PathSymlink,
                &path_symlink.rules,
            )?);
        }
        if let Some(path_chmod) = &config.path_chmod
            && path_chmod.enabled
        {
            hooks.push(HookData::new(FileMonHook::PathChmod, &path_chmod.rules)?);
        }
        if let Some(path_chown) = &config.path_chown
            && path_chown.enabled
        {
            hooks.push(HookData::new(FileMonHook::PathChown, &path_chown.rules)?);
        }
        if let Some(sb_mount) = &config.sb_mount
            && sb_mount.enabled
        {
            hooks.push(HookData::new(FileMonHook::SbMount, &sb_mount.rules)?);
        }
        if let Some(mmap_file) = &config.mmap_file
            && mmap_file.enabled
        {
            hooks.push(HookData::new(FileMonHook::MmapFile, &mmap_file.rules)?);
        }
        if let Some(file_ioctl) = &config.file_ioctl
            && file_ioctl.enabled
        {
            hooks.push(HookData::new(FileMonHook::FileIoctl, &file_ioctl.rules)?);
        }

        resize_all_filemon_maps(&hooks, ebpf_loader_ref)?;

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(FileMonNew { ebpf, hooks })
    }
}

impl Detector for FileMonNew {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        // TODO: Change trait error type to anyhow::Error
        init_all_filemon_maps(&self.hooks, &mut self.ebpf).map_err(|e| MapError::InvalidName {
            name: e.to_string(),
        })?;
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        for hook in &self.hooks {
            let (hook_name, load) = match hook.hook {
                FileMonHook::FileOpen => ("file_open", true),
                hook_enum_value => {
                    unimplemented!("Cannot load hook: {hook_enum_value:?}")
                }
            };
            if load {
                let open: &mut Lsm = self
                    .ebpf
                    .program_mut(&format!("{hook_name}_modified"))
                    .unwrap()
                    .try_into()?;
                open.load(hook_name, &btf)?;
                open.attach()?;
            }
        }
        Ok(())
    }
}

#[inline]
fn resize_all_filemon_maps<'a>(
    hooks: &'a [HookData],
    loader: &mut EbpfLoader<'a>,
) -> Result<(), anyhow::Error> {
    let kernel_ver = Version::current()?;
    let ver_6_8 = Version::new(6, 8, 0);

    for hook in hooks {
        let load = match hook.hook {
            FileMonHook::FileOpen
            | FileMonHook::PathChmod
            | FileMonHook::SbMount
            | FileMonHook::MmapFile
            | FileMonHook::FileIoctl => true,
            FileMonHook::PathTruncate
            | FileMonHook::PathUnlink
            | FileMonHook::PathSymlink
            | FileMonHook::PathChown => kernel_ver >= ver_6_8,
        };
        if load {
            hook.map_sizes.iter().for_each(|(name, size)| {
                loader.set_max_entries(name, *size);
            });
        }
    }
    Ok(())
}

fn init_all_filemon_maps(hooks: &[HookData], ebpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    let kernel_ver = Version::current()?;
    let ver_6_8 = Version::new(6, 8, 0);
    for hook in hooks {
        let load = match hook.hook {
            FileMonHook::FileOpen
            | FileMonHook::PathChmod
            | FileMonHook::SbMount
            | FileMonHook::MmapFile
            | FileMonHook::FileIoctl => true,
            FileMonHook::PathTruncate
            | FileMonHook::PathUnlink
            | FileMonHook::PathSymlink
            | FileMonHook::PathChown => kernel_ver >= ver_6_8,
        };
        if load {
            hook.serialized_rules
                .store_rules(ebpf, hook.hook.map_prefix())?;
        }
    }

    Ok(())
}
