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
    config::{filemon::Config, procmon::ProcessFilterMask},
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
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(FileMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            filter_mask: ProcessFilterMask::empty(),
            deny_list: false,
        };
        if let Some(filter) = &self.config.process_filter {
            config.filter_mask = init_process_filter_maps!(filter, &mut self.ebpf);
            config.deny_list = filter.deny_list;
        }

        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("FILEMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;

        if let Some(open_cfg) = self.config.file_open {
            if !open_cfg.disable {
                let open: &mut Lsm = self
                    .ebpf
                    .program_mut("file_open_capture")
                    .unwrap()
                    .try_into()?;
                open.load("file_open", &btf)?;
                open.attach()?;
            }
        }
        if let Some(truncate_cfg) = self.config.path_truncate {
            if !truncate_cfg.disable {
                let truncate: &mut Lsm = self
                    .ebpf
                    .program_mut("path_truncate_capture")
                    .unwrap()
                    .try_into()?;
                truncate.load("path_truncate", &btf)?;
                truncate.attach()?;
            }
        }
        if let Some(unlink_cfg) = self.config.path_unlink {
            if !unlink_cfg.disable {
                let unlink: &mut Lsm = self
                    .ebpf
                    .program_mut("path_unlink_capture")
                    .unwrap()
                    .try_into()?;
                unlink.load("path_unlink", &btf)?;
                unlink.attach()?;
            }
        }
        if let Some(chmod_cfg) = self.config.path_chmod {
            if !chmod_cfg.disable {
                let chmod: &mut Lsm = self
                    .ebpf
                    .program_mut("path_chmod_capture")
                    .unwrap()
                    .try_into()?;
                chmod.load("path_chmod", &btf)?;
                chmod.attach()?;
            }
        }
        if let Some(chown_cfg) = self.config.path_chown {
            if !chown_cfg.disable {
                let chown: &mut Lsm = self
                    .ebpf
                    .program_mut("path_chown_capture")
                    .unwrap()
                    .try_into()?;
                chown.load("path_chown", &btf)?;
                chown.attach()?;
            }
        }
        if let Some(sb_mount_cfg) = self.config.sb_mount {
            if !sb_mount_cfg.disable {
                let sb_mount: &mut Lsm = self
                    .ebpf
                    .program_mut("sb_mount_capture")
                    .unwrap()
                    .try_into()?;
                sb_mount.load("sb_mount", &btf)?;
                sb_mount.attach()?;
            }
        }
        if let Some(mmap_file_cfg) = self.config.mmap_file {
            if !mmap_file_cfg.disable {
                let mmap_file: &mut Lsm = self
                    .ebpf
                    .program_mut("mmap_file_capture")
                    .unwrap()
                    .try_into()?;
                mmap_file.load("mmap_file", &btf)?;
                mmap_file.attach()?;
            }
        }
        Ok(())
    }
}

/// FileMon Filter map names
const FILTER_UID_MAP_NAME: &str = "FILEMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "FILEMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "FILEMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "FILEMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "FILEMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "FILEMON_FILTER_BINPREFIX_MAP";
