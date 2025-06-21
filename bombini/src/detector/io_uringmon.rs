//! IOUring detector

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::BtfTracePoint;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

use bombini_common::{
    config::io_uringmon::Config,
    config::procmon::ProcessFilterMask,
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

pub struct IOUringMon {
    ebpf: Ebpf,
    /// User supplied config
    config: IOUringMonConfig,
}

impl Detector for IOUringMon {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let Some(yaml_config) = yaml_config else {
            anyhow::bail!("Config for io_uringmon must be provided");
        };
        let docs = YamlLoader::load_from_str(yaml_config.as_ref())?;
        let doc = &docs[0];

        let config_opts = CONFIG.read().await;
        let config = IOUringMonConfig::new(doc)?;
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
        Ok(IOUringMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            expose_events: false,
            filter_mask: ProcessFilterMask::empty(),
            deny_list: false,
        };
        config.expose_events = self.config.expose_events;
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
            Array::try_from(self.ebpf.map_mut("IOURINGMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let submit: &mut BtfTracePoint = self
            .ebpf
            .program_mut("io_uring_submit_req_capture")
            .unwrap()
            .try_into()?;
        submit.load("io_uring_submit_req", &btf)?;
        submit.attach()?;
        Ok(())
    }
}

/// Yaml provided user config
struct IOUringMonConfig {
    pub expose_events: bool,
    pub filter: Option<ProcessFilter>,
}

impl IOUringMonConfig {
    pub fn new(yaml: &Yaml) -> Result<Self, anyhow::Error> {
        let Some(yaml) = yaml.as_hash() else {
            anyhow::bail!("yaml must be a hash")
        };
        if yaml.contains_key(&Yaml::from_str("process_allow_list"))
            && yaml.contains_key(&Yaml::from_str("process_deny_list"))
        {
            anyhow::bail!("config supports only allow or deny list");
        }
        let Some(expose_events) = yaml.get(&Yaml::from_str("expose-events")) else {
            anyhow::bail!("expose-events must be set")
        };
        if let Some(filter) = yaml.get(&Yaml::from_str("process_allow_list")) {
            Ok(IOUringMonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: Some(ProcessFilter::AllowList(ProcessFilterConfig::new(filter)?)),
            })
        } else if let Some(filter) = yaml.get(&Yaml::from_str("process_deny_list")) {
            Ok(IOUringMonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: Some(ProcessFilter::DenyList(ProcessFilterConfig::new(filter)?)),
            })
        } else {
            Ok(IOUringMonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: None,
            })
        }
    }
}

/// IOUringMon Filter map names
const FILTER_UID_MAP_NAME: &str = "IOURINGMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "IOURINGMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "IOURINGMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "IOURINGMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "IOURINGMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "IOURINGMON_FILTER_BINPREFIX_MAP";
