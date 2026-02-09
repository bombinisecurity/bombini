use std::{collections::HashMap, path::Path, sync::Arc};

use crate::detector::{Detector, Version};
use crate::rule::serializer::PredicateSerializer;
use crate::rule::serializer::filemon::{
    FileIoctlPredicate, FileOpenPredicate, MmapFilePredicate, PathChmodPredicate,
    PathChownPredicate, PathSymlinkPredicate, PathTruncatePredicate, PathUnlinkPredicate,
    SbMountPredicate,
};
use aya::maps::MapError;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use crate::proto::config::{FileMonNewConfig, Rule};
use crate::rule::serializer::SerializedRules;

pub struct FileMonNew {
    ebpf: Ebpf,
    hooks: Vec<Box<dyn FileMonRuleContainer>>,
}

trait FileMonRuleContainer {
    fn map_sizes(&self) -> &HashMap<String, u32>;
    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error>;
    fn hook(&self) -> FileMonHook;
}

#[derive(Debug)]
struct HookData<T: PredicateSerializer> {
    hook: FileMonHook,
    serialized_rules: SerializedRules<T>,
    map_sizes: HashMap<String, u32>,
}

impl<T: PredicateSerializer + Default> HookData<T> {
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

impl<T: PredicateSerializer> FileMonRuleContainer for HookData<T> {
    fn map_sizes(&self) -> &HashMap<String, u32> {
        &self.map_sizes
    }

    fn store_rules(&self, ebpf: &mut Ebpf, map_prefix: &'static str) -> Result<(), anyhow::Error> {
        self.serialized_rules.store_rules(ebpf, map_prefix)
    }

    fn hook(&self) -> FileMonHook {
        self.hook
    }
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

        let mut hooks: Vec<Box<dyn FileMonRuleContainer>> = Vec::new();
        if let Some(file_open) = &config.file_open
            && file_open.enabled
        {
            hooks.push(Box::new(HookData::<FileOpenPredicate>::new(
                FileMonHook::FileOpen,
                &file_open.rules,
            )?));
        }
        if let Some(path_truncate) = &config.path_truncate
            && path_truncate.enabled
        {
            hooks.push(Box::new(HookData::<PathTruncatePredicate>::new(
                FileMonHook::PathTruncate,
                &path_truncate.rules,
            )?));
        }
        if let Some(path_unlink) = &config.path_unlink
            && path_unlink.enabled
        {
            hooks.push(Box::new(HookData::<PathUnlinkPredicate>::new(
                FileMonHook::PathUnlink,
                &path_unlink.rules,
            )?));
        }
        if let Some(path_symlink) = &config.path_symlink
            && path_symlink.enabled
        {
            hooks.push(Box::new(HookData::<PathSymlinkPredicate>::new(
                FileMonHook::PathSymlink,
                &path_symlink.rules,
            )?));
        }
        if let Some(path_chmod) = &config.path_chmod
            && path_chmod.enabled
        {
            hooks.push(Box::new(HookData::<PathChmodPredicate>::new(
                FileMonHook::PathChmod,
                &path_chmod.rules,
            )?));
        }
        if let Some(path_chown) = &config.path_chown
            && path_chown.enabled
        {
            hooks.push(Box::new(HookData::<PathChownPredicate>::new(
                FileMonHook::PathChown,
                &path_chown.rules,
            )?));
        }
        if let Some(sb_mount) = &config.sb_mount
            && sb_mount.enabled
        {
            hooks.push(Box::new(HookData::<SbMountPredicate>::new(
                FileMonHook::SbMount,
                &sb_mount.rules,
            )?));
        }
        if let Some(mmap_file) = &config.mmap_file
            && mmap_file.enabled
        {
            hooks.push(Box::new(HookData::<MmapFilePredicate>::new(
                FileMonHook::MmapFile,
                &mmap_file.rules,
            )?));
        }
        if let Some(file_ioctl) = &config.file_ioctl
            && file_ioctl.enabled
        {
            hooks.push(Box::new(HookData::<FileIoctlPredicate>::new(
                FileMonHook::FileIoctl,
                &file_ioctl.rules,
            )?));
        }

        resize_all_filemon_maps(hooks.as_slice(), ebpf_loader_ref)?;

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
        let kernel_ver = Version::current().expect("Cannot get kernel version");
        let ver_6_8 = Version::new(6, 8, 0);
        for hook in &self.hooks {
            let (hook_name, load) = match hook.hook() {
                FileMonHook::FileOpen => ("file_open", true),
                FileMonHook::PathTruncate => ("path_truncate", kernel_ver >= ver_6_8),
                FileMonHook::PathUnlink => ("path_unlink", kernel_ver >= ver_6_8),
                FileMonHook::PathSymlink => ("path_symlink", kernel_ver >= ver_6_8),
                FileMonHook::PathChmod => ("path_chmod", kernel_ver >= ver_6_8),
                FileMonHook::PathChown => ("path_chown", kernel_ver >= ver_6_8),
                FileMonHook::SbMount => ("sb_mount", true),
                FileMonHook::MmapFile => ("mmap_file", true),
                FileMonHook::FileIoctl => ("file_ioctl", true),
            };
            if load {
                let program: &mut Lsm = self
                    .ebpf
                    .program_mut(&format!("{hook_name}_modified"))
                    .unwrap()
                    .try_into()?;
                program.load(hook_name, &btf)?;
                program.attach()?;
            } else {
                log::warn!("Cannot load hook: {hook_name}. Kernel version is too old.");
            }
        }
        Ok(())
    }
}

#[inline]
fn resize_all_filemon_maps<'a>(
    hooks: &'a [Box<dyn FileMonRuleContainer>],
    loader: &mut EbpfLoader<'a>,
) -> Result<(), anyhow::Error> {
    let kernel_ver = Version::current()?;
    let ver_6_8 = Version::new(6, 8, 0);

    for hook in hooks {
        let load = match hook.hook() {
            FileMonHook::SbMount => false,
            FileMonHook::FileOpen | FileMonHook::MmapFile | FileMonHook::FileIoctl => true,
            FileMonHook::PathTruncate
            | FileMonHook::PathChmod
            | FileMonHook::PathUnlink
            | FileMonHook::PathSymlink
            | FileMonHook::PathChown => kernel_ver >= ver_6_8,
        };
        if load {
            hook.map_sizes()
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    loader.set_max_entries(name, *size);
                });
        }
    }
    Ok(())
}

fn init_all_filemon_maps(
    hooks: &[Box<dyn FileMonRuleContainer>],
    ebpf: &mut Ebpf,
) -> Result<(), anyhow::Error> {
    let kernel_ver = Version::current()?;
    let ver_6_8 = Version::new(6, 8, 0);
    for hook in hooks {
        let load = match hook.hook() {
            FileMonHook::SbMount => false,
            FileMonHook::FileOpen | FileMonHook::MmapFile | FileMonHook::FileIoctl => true,
            FileMonHook::PathTruncate
            | FileMonHook::PathChmod
            | FileMonHook::PathUnlink
            | FileMonHook::PathSymlink
            | FileMonHook::PathChown => kernel_ver >= ver_6_8,
        };
        if load {
            hook.store_rules(ebpf, hook.hook().map_prefix())?;
        }
    }

    Ok(())
}
