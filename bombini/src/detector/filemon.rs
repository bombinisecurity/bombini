//! File monitor detector

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use std::path::Path;

use bombini_common::{
    config::{filemon::Config, filemon::PathFilterMask, procmon::ProcessFilterMask},
    constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX},
};

use crate::{
    config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME},
    init_process_filter_maps,
    proto::config::FileMonConfig,
    resize_process_filter_maps,
};

use super::Detector;

pub struct FileMon {
    ebpf: Ebpf,
    config: FileMonConfig,
}

impl Detector for FileMon {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let Some(yaml_config) = yaml_config else {
            anyhow::bail!("Config for filemon must be provided");
        };

        let config: FileMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
        let config_opts = CONFIG.read().await;
        let mut ebpf_loader = EbpfLoader::new();
        let mut ebpf_loader_ref = ebpf_loader
            .map_pin_path(config_opts.maps_pin_path.as_ref().unwrap())
            .set_max_entries(EVENT_MAP_NAME, config_opts.event_map_size.unwrap())
            .set_max_entries(
                PROCMON_PROC_MAP_NAME,
                config_opts.procmon_proc_map_size.unwrap(),
            );
        if let Some(filter) = &config.process_filter {
            resize_process_filter_maps!(filter, ebpf_loader_ref);
        }

        resize_all_path_filter_maps(&config, ebpf_loader_ref);

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(FileMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            filter_mask: ProcessFilterMask::empty(),
            path_mask: [PathFilterMask::empty(); 8],
            deny_list: false,
        };
        if let Some(filter) = &self.config.process_filter {
            config.filter_mask = init_process_filter_maps!(filter, &mut self.ebpf);
            config.deny_list = filter.deny_list;
        }

        intit_all_path_filter_maps(&mut config, &self.config, &mut self.ebpf)?;
        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("FILEMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;

        if let Some(ref open_cfg) = self.config.file_open {
            if open_cfg.enabled {
                let open: &mut Lsm = self
                    .ebpf
                    .program_mut("file_open_capture")
                    .unwrap()
                    .try_into()?;
                open.load("file_open", &btf)?;
                open.attach()?;
            }
        }
        if let Some(ref truncate_cfg) = self.config.path_truncate {
            if truncate_cfg.enabled {
                let truncate: &mut Lsm = self
                    .ebpf
                    .program_mut("path_truncate_capture")
                    .unwrap()
                    .try_into()?;
                truncate.load("path_truncate", &btf)?;
                truncate.attach()?;
            }
        }
        if let Some(ref unlink_cfg) = self.config.path_unlink {
            if unlink_cfg.enabled {
                let unlink: &mut Lsm = self
                    .ebpf
                    .program_mut("path_unlink_capture")
                    .unwrap()
                    .try_into()?;
                unlink.load("path_unlink", &btf)?;
                unlink.attach()?;
            }
        }
        if let Some(ref chmod_cfg) = self.config.path_chmod {
            if chmod_cfg.enabled {
                let chmod: &mut Lsm = self
                    .ebpf
                    .program_mut("path_chmod_capture")
                    .unwrap()
                    .try_into()?;
                chmod.load("path_chmod", &btf)?;
                chmod.attach()?;
            }
        }
        if let Some(ref chown_cfg) = self.config.path_chown {
            if chown_cfg.enabled {
                let chown: &mut Lsm = self
                    .ebpf
                    .program_mut("path_chown_capture")
                    .unwrap()
                    .try_into()?;
                chown.load("path_chown", &btf)?;
                chown.attach()?;
            }
        }
        if let Some(ref sb_mount_cfg) = self.config.sb_mount {
            if sb_mount_cfg.enabled {
                let sb_mount: &mut Lsm = self
                    .ebpf
                    .program_mut("sb_mount_capture")
                    .unwrap()
                    .try_into()?;
                sb_mount.load("sb_mount", &btf)?;
                sb_mount.attach()?;
            }
        }
        if let Some(ref mmap_file_cfg) = self.config.mmap_file {
            if mmap_file_cfg.enabled {
                let mmap_file: &mut Lsm = self
                    .ebpf
                    .program_mut("mmap_file_capture")
                    .unwrap()
                    .try_into()?;
                mmap_file.load("mmap_file", &btf)?;
                mmap_file.attach()?;
            }
        }
        if let Some(ref file_ioctl_cfg) = self.config.file_ioctl {
            if file_ioctl_cfg.enabled {
                let file_ioctl: &mut Lsm = self
                    .ebpf
                    .program_mut("file_ioctl_capture")
                    .unwrap()
                    .try_into()?;
                file_ioctl.load("file_ioctl", &btf)?;
                file_ioctl.attach()?;
            }
        }
        Ok(())
    }
}

macro_rules! resize_path_filter_maps {
    ($filter_config:expr, $ebpf_loader_ref:expr, $name_map:expr, $path_map:expr, $prefix_map:expr) => {
        if $filter_config.name.len() > 1 {
            $ebpf_loader_ref.set_max_entries($name_map, $filter_config.name.len() as u32);
        }
        if $filter_config.path.len() > 1 {
            $ebpf_loader_ref.set_max_entries($path_map, $filter_config.path.len() as u32);
        }
        if $filter_config.prefix.len() > 1 {
            $ebpf_loader_ref.set_max_entries($prefix_map, $filter_config.prefix.len() as u32);
        }
    };
}

#[inline]
fn resize_all_path_filter_maps(config: &FileMonConfig, loader: &mut EbpfLoader) {
    if let Some(ref file_open_cfg) = config.file_open {
        if let Some(ref filter) = file_open_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_OPEN_NAME_MAP,
                FILTER_OPEN_PATH_MAP,
                FILTER_OPEN_PREFIX_MAP
            );
        }
    }
    if let Some(ref truncate_cfg) = config.path_truncate {
        if let Some(ref filter) = truncate_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_TRUNC_NAME_MAP,
                FILTER_TRUNC_PATH_MAP,
                FILTER_TRUNC_PREFIX_MAP
            );
        }
    }
    if let Some(ref chmod_cfg) = config.path_chmod {
        if let Some(ref filter) = chmod_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_CHMOD_NAME_MAP,
                FILTER_CHMOD_PATH_MAP,
                FILTER_CHMOD_PREFIX_MAP
            );
        }
    }
    if let Some(ref chown_cfg) = config.path_chown {
        if let Some(ref filter) = chown_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_CHOWN_NAME_MAP,
                FILTER_CHOWN_PATH_MAP,
                FILTER_CHOWN_PREFIX_MAP
            );
        }
    }
    if let Some(ref mmap_cfg) = config.mmap_file {
        if let Some(ref filter) = mmap_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_MMAP_NAME_MAP,
                FILTER_MMAP_PATH_MAP,
                FILTER_MMAP_PREFIX_MAP
            );
        }
    }
    if let Some(ref ioctl_cfg) = config.file_ioctl {
        if let Some(ref filter) = ioctl_cfg.path_filter {
            resize_path_filter_maps!(
                filter,
                loader,
                FILTER_IOCTL_NAME_MAP,
                FILTER_IOCTL_PATH_MAP,
                FILTER_IOCTL_PREFIX_MAP
            );
        }
    }
}

macro_rules! init_path_filter_maps {
    ($filter_config:expr, $ebpf:expr, $name_map:expr, $path_map:expr, $prefix_map:expr) => {{
        let mut filter_mask = PathFilterMask::empty();
        if !$filter_config.name.is_empty() {
            let mut bname_map: HashMap<_, [u8; MAX_FILENAME_SIZE], u8> =
                HashMap::try_from($ebpf.map_mut($name_map).unwrap())?;
            for name in $filter_config.name.iter() {
                let mut v = [0u8; MAX_FILENAME_SIZE];
                let name_bytes = name.as_bytes();
                let len = name_bytes.len();
                if len < MAX_FILENAME_SIZE {
                    v[..len].clone_from_slice(name_bytes);
                } else {
                    v.clone_from_slice(&name_bytes[..MAX_FILENAME_SIZE]);
                }
                let _ = bname_map.insert(v, 0, 0);
            }
            filter_mask |= PathFilterMask::NAME;
        }
        if !$filter_config.path.is_empty() {
            let mut bpath_map: HashMap<_, [u8; MAX_FILE_PATH], u8> =
                HashMap::try_from($ebpf.map_mut($path_map).unwrap())?;
            for path in $filter_config.path.iter() {
                let mut v = [0u8; MAX_FILE_PATH];
                let path_bytes = path.as_bytes();
                let len = path_bytes.len();
                if len < MAX_FILE_PATH {
                    v[..len].clone_from_slice(path_bytes);
                } else {
                    v.clone_from_slice(&path_bytes[..MAX_FILE_PATH]);
                }
                let _ = bpath_map.insert(v, 0, 0);
            }
            filter_mask |= PathFilterMask::PATH;
        }
        if !$filter_config.prefix.is_empty() {
            let mut bprefix_map: LpmTrie<_, [u8; MAX_FILE_PREFIX], u8> =
                LpmTrie::try_from($ebpf.map_mut($prefix_map).unwrap())?;
            for prefix in $filter_config.prefix.iter() {
                let mut v = [0u8; MAX_FILE_PREFIX];
                let prefix_bytes = prefix.as_bytes();
                let len = prefix_bytes.len();
                if len < MAX_FILE_PREFIX {
                    v[..len].clone_from_slice(prefix_bytes);
                } else {
                    v.clone_from_slice(&prefix_bytes[..MAX_FILE_PREFIX]);
                }
                let key = Key::new((prefix.len() * 8) as u32, v);
                let _ = bprefix_map.insert(&key, 0, 0);
            }
            filter_mask |= PathFilterMask::PATH_PREFIX;
        }
        filter_mask
    }};
}

#[inline]
fn intit_all_path_filter_maps(
    ebpf_config: &mut Config,
    config: &FileMonConfig,
    ebpf: &mut Ebpf,
) -> Result<(), EbpfError> {
    if let Some(ref file_open_cfg) = config.file_open {
        if let Some(ref filter) = file_open_cfg.path_filter {
            ebpf_config.path_mask[0] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_OPEN_NAME_MAP,
                FILTER_OPEN_PATH_MAP,
                FILTER_OPEN_PREFIX_MAP
            );
        }
    }
    if let Some(ref truncate_cfg) = config.path_truncate {
        if let Some(ref filter) = truncate_cfg.path_filter {
            ebpf_config.path_mask[1] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_TRUNC_NAME_MAP,
                FILTER_TRUNC_PATH_MAP,
                FILTER_TRUNC_PREFIX_MAP
            );
        }
    }
    if let Some(ref chmod_cfg) = config.path_chmod {
        if let Some(ref filter) = chmod_cfg.path_filter {
            ebpf_config.path_mask[3] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_CHMOD_NAME_MAP,
                FILTER_CHMOD_PATH_MAP,
                FILTER_CHMOD_PREFIX_MAP
            );
        }
    }
    if let Some(ref chown_cfg) = config.path_chown {
        if let Some(ref filter) = chown_cfg.path_filter {
            ebpf_config.path_mask[4] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_CHOWN_NAME_MAP,
                FILTER_CHOWN_PATH_MAP,
                FILTER_CHOWN_PREFIX_MAP
            );
        }
    }
    if let Some(ref mmap_cfg) = config.mmap_file {
        if let Some(ref filter) = mmap_cfg.path_filter {
            ebpf_config.path_mask[6] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_MMAP_NAME_MAP,
                FILTER_MMAP_PATH_MAP,
                FILTER_MMAP_PREFIX_MAP
            );
        }
    }
    if let Some(ref ioctl_cfg) = config.file_ioctl {
        if let Some(ref filter) = ioctl_cfg.path_filter {
            ebpf_config.path_mask[7] = init_path_filter_maps!(
                filter,
                ebpf,
                FILTER_IOCTL_NAME_MAP,
                FILTER_IOCTL_PATH_MAP,
                FILTER_IOCTL_PREFIX_MAP
            );
        }
    }
    Ok(())
}

/// FileMon Filter map names
const FILTER_UID_MAP_NAME: &str = "FILEMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "FILEMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "FILEMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "FILEMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "FILEMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "FILEMON_FILTER_BINPREFIX_MAP";

// File Open path filter maps
const FILTER_OPEN_PATH_MAP: &str = "FILEMON_FILTER_OPEN_PATH_MAP";

const FILTER_OPEN_NAME_MAP: &str = "FILEMON_FILTER_OPEN_NAME_MAP";

const FILTER_OPEN_PREFIX_MAP: &str = "FILEMON_FILTER_OPEN_PREFIX_MAP";

// Path truncate filter maps
const FILTER_TRUNC_PATH_MAP: &str = "FILEMON_FILTER_TRUNC_PATH_MAP";

const FILTER_TRUNC_NAME_MAP: &str = "FILEMON_FILTER_TRUNC_NAME_MAP";

const FILTER_TRUNC_PREFIX_MAP: &str = "FILEMON_FILTER_TRUNC_PREFIX_MAP";

// Path chmod filter maps
const FILTER_CHMOD_PATH_MAP: &str = "FILEMON_FILTER_CHMOD_PATH_MAP";

const FILTER_CHMOD_NAME_MAP: &str = "FILEMON_FILTER_CHMOD_NAME_MAP";

const FILTER_CHMOD_PREFIX_MAP: &str = "FILEMON_FILTER_CHMOD_PREFIX_MAP";

// Path chown filter maps
const FILTER_CHOWN_PATH_MAP: &str = "FILEMON_FILTER_CHOWN_PATH_MAP";

const FILTER_CHOWN_NAME_MAP: &str = "FILEMON_FILTER_CHOWN_NAME_MAP";

const FILTER_CHOWN_PREFIX_MAP: &str = "FILEMON_FILTER_CHOWN_PREFIX_MAP";

// Mmap path filter maps
const FILTER_MMAP_PATH_MAP: &str = "FILEMON_FILTER_MMAP_PATH_MAP";

const FILTER_MMAP_NAME_MAP: &str = "FILEMON_FILTER_MMAP_NAME_MAP";

const FILTER_MMAP_PREFIX_MAP: &str = "FILEMON_FILTER_MMAP_PREFIX_MAP";

// Ioctl path filter maps
const FILTER_IOCTL_PATH_MAP: &str = "FILEMON_FILTER_IOCTL_PATH_MAP";

const FILTER_IOCTL_NAME_MAP: &str = "FILEMON_FILTER_IOCTL_NAME_MAP";

const FILTER_IOCTL_PREFIX_MAP: &str = "FILEMON_FILTER_IOCTL_PREFIX_MAP";
