//! File monitor detector

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use yaml_rust2::{Yaml, YamlLoader};

use std::path::Path;

use bombini_common::{
    config::{filemon::Config, procmon::ProcessFilterMask},
    constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX},
};

use crate::{
    config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME},
    init_process_filter_maps, resize_process_filter_maps,
};

use super::{
    procmon::{ProcessFilter, ProcessFilterConfig},
    Detector,
};

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
        let docs = YamlLoader::load_from_str(yaml_config.as_ref())?;
        let doc = &docs[0];

        let config_opts = CONFIG.read().await;
        let config = FileMonConfig::new(doc)?;
        let mut ebpf_loader = EbpfLoader::new();
        let mut ebpf_loader_ref = ebpf_loader
            .map_pin_path(config_opts.maps_pin_path.as_ref().unwrap())
            .set_max_entries(EVENT_MAP_NAME, config_opts.event_map_size.unwrap())
            .set_max_entries(
                PROCMON_PROC_MAP_NAME,
                config_opts.procmon_proc_map_size.unwrap(),
            );
        if let Some(filter) = &config.filter {
            let filter_config = match filter {
                ProcessFilter::AllowList(f) => f,
                ProcessFilter::DenyList(f) => f,
            };
            resize_process_filter_maps!(filter_config, ebpf_loader_ref);
        }
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(FileMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            filter_mask: ProcessFilterMask::empty(),
            deny_list: false,
        };
        if let Some(filter) = &self.config.filter {
            let filter_config = match filter {
                ProcessFilter::AllowList(f) => f,
                ProcessFilter::DenyList(f) => {
                    config.deny_list = true;
                    f
                }
            };
            config.filter_mask = init_process_filter_maps!(filter_config, &mut self.ebpf);
        }

        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("FILEMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;

        if !self.config.open.disable {
            let open: &mut Lsm = self
                .ebpf
                .program_mut("file_open_capture")
                .unwrap()
                .try_into()?;
            open.load("file_open", &btf)?;
            open.attach()?;
        }
        if !self.config.truncate.disable {
            let truncate: &mut Lsm = self
                .ebpf
                .program_mut("path_truncate_capture")
                .unwrap()
                .try_into()?;
            truncate.load("path_truncate", &btf)?;
            truncate.attach()?;
        }
        if !self.config.unlink.disable {
            let unlink: &mut Lsm = self
                .ebpf
                .program_mut("path_unlink_capture")
                .unwrap()
                .try_into()?;
            unlink.load("path_unlink", &btf)?;
            unlink.attach()?;
        }
        Ok(())
    }
}

/// Yaml provided user config
#[derive(Default)]
struct FileMonConfig {
    pub open: FileHookConfig,
    pub truncate: FileHookConfig,
    pub unlink: FileHookConfig,
    pub filter: Option<ProcessFilter>,
}

impl FileMonConfig {
    pub fn new(yaml: &Yaml) -> Result<Self, anyhow::Error> {
        let Some(yaml) = yaml.as_hash() else {
            anyhow::bail!("yaml must be a hash")
        };
        let mut config = Self::default();
        if let Some(hook) = yaml.get(&Yaml::from_str("file-open")) {
            config.open = FileHookConfig::new(hook)?;
        }

        if let Some(hook) = yaml.get(&Yaml::from_str("path-truncate")) {
            config.truncate = FileHookConfig::new(hook)?;
        }

        if let Some(hook) = yaml.get(&Yaml::from_str("path-unlink")) {
            config.unlink = FileHookConfig::new(hook)?;
        }
        if let Some(filter) = yaml.get(&Yaml::from_str("process_allow_list")) {
            config.filter = Some(ProcessFilter::AllowList(ProcessFilterConfig::new(filter)?));
        } else if let Some(filter) = yaml.get(&Yaml::from_str("process_deny_list")) {
            config.filter = Some(ProcessFilter::DenyList(ProcessFilterConfig::new(filter)?));
        }
        Ok(config)
    }
}

#[derive(Default)]
struct FileHookConfig {
    pub disable: bool,
}

impl FileHookConfig {
    pub fn new(yaml: &Yaml) -> Result<Self, anyhow::Error> {
        let Some(yaml) = yaml.as_hash() else {
            anyhow::bail!("yaml must be a hash")
        };

        let mut config = Self::default();
        if let Some(disable) = yaml.get(&Yaml::from_str("disable")) {
            config.disable = disable.as_bool().unwrap_or(false);
        }
        Ok(config)
    }
}

/// FileMon Filter map names
const FILTER_UID_MAP_NAME: &str = "FILEMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "FILEMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "FILEMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "FILEMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "FILEMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "FILEMON_FILTER_BINPREFIX_MAP";
