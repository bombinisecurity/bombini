//! Detector for Process executions and exits

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::{BtfTracePoint, FEntry, Lsm};
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use yaml_rust2::{Yaml, YamlLoader};

use std::path::Path;

use bombini_common::{
    config::procmon::{Config, ProcessFilterMask},
    constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX},
};

use crate::config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME};

use super::Detector;

pub struct ProcMon {
    /// aya::Ebpf object
    ebpf: Ebpf,
    /// User supplied config
    config: ProcmonConfig,
}

impl Detector for ProcMon {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let Some(yaml_config) = yaml_config else {
            anyhow::bail!("Config for procmon must be provided");
        };
        let docs = YamlLoader::load_from_str(yaml_config.as_ref())?;
        let doc = &docs[0];

        let config_opts = CONFIG.read().await;
        let config = ProcmonConfig::new(doc)?;
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
            if filter_config.uid.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref
                    .set_max_entries(FILTER_UID_MAP_NAME, filter_config.uid.len() as u32);
            }
            if filter_config.euid.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref
                    .set_max_entries(FILTER_EUID_MAP_NAME, filter_config.euid.len() as u32);
            }
            if filter_config.auid.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref
                    .set_max_entries(FILTER_AUID_MAP_NAME, filter_config.auid.len() as u32);
            }
            if filter_config.binary_name.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref.set_max_entries(
                    FILTER_BINNAME_MAP_NAME,
                    filter_config.binary_name.len() as u32,
                );
            }
            if filter_config.binary_path.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref.set_max_entries(
                    FILTER_BINPATH_MAP_NAME,
                    filter_config.binary_path.len() as u32,
                );
            }
            if filter_config.binary_prefix.len() > 1 {
                ebpf_loader_ref = ebpf_loader_ref.set_max_entries(
                    FILTER_BINPREFIX_MAP_NAME,
                    filter_config.binary_prefix.len() as u32,
                );
            }
        }

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(ProcMon { ebpf, config })
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
            if !filter_config.uid.is_empty() {
                let mut uid_map: HashMap<_, u32, u8> =
                    HashMap::try_from(self.ebpf.map_mut(FILTER_UID_MAP_NAME).unwrap())?;
                for v in filter_config.uid.iter() {
                    let _ = uid_map.insert(v, 0, 0);
                }
                config.filter_mask |= ProcessFilterMask::UID;
            }
            if !filter_config.euid.is_empty() {
                let mut euid_map: HashMap<_, u32, u8> =
                    HashMap::try_from(self.ebpf.map_mut(FILTER_EUID_MAP_NAME).unwrap())?;
                for v in filter_config.euid.iter() {
                    let _ = euid_map.insert(v, 0, 0);
                }
                config.filter_mask |= ProcessFilterMask::EUID;
            }
            if !filter_config.auid.is_empty() {
                let mut auid_map: HashMap<_, u32, u8> =
                    HashMap::try_from(self.ebpf.map_mut(FILTER_AUID_MAP_NAME).unwrap())?;
                for v in filter_config.auid.iter() {
                    let _ = auid_map.insert(v, 0, 0);
                }
                config.filter_mask |= ProcessFilterMask::AUID;
            }
            if !filter_config.binary_name.is_empty() {
                let mut bname_map: HashMap<_, [u8; MAX_FILENAME_SIZE], u8> =
                    HashMap::try_from(self.ebpf.map_mut(FILTER_BINNAME_MAP_NAME).unwrap())?;
                for name in filter_config.binary_name.iter() {
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
                config.filter_mask |= ProcessFilterMask::BINARY_NAME;
            }
            if !filter_config.binary_path.is_empty() {
                let mut bpath_map: HashMap<_, [u8; MAX_FILE_PATH], u8> =
                    HashMap::try_from(self.ebpf.map_mut(FILTER_BINPATH_MAP_NAME).unwrap())?;
                for path in filter_config.binary_path.iter() {
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
                config.filter_mask |= ProcessFilterMask::BINARY_PATH;
            }
            if !filter_config.binary_prefix.is_empty() {
                let mut bprefix_map: LpmTrie<_, [u8; MAX_FILE_PREFIX], u8> =
                    LpmTrie::try_from(self.ebpf.map_mut(FILTER_BINPREFIX_MAP_NAME).unwrap())?;
                for prefix in filter_config.binary_prefix.iter() {
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
                config.filter_mask |= ProcessFilterMask::BINARY_PATH_PREFIX;
            }
        }
        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("PROCMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let exec: &mut BtfTracePoint = self
            .ebpf
            .program_mut("execve_capture")
            .unwrap()
            .try_into()?;
        exec.load("sched_process_exec", &btf)?;
        exec.attach()?;

        let fork: &mut FEntry = self.ebpf.program_mut("fork_capture").unwrap().try_into()?;
        fork.load("wake_up_new_task", &btf)?;
        fork.attach()?;

        let exit: &mut FEntry = self.ebpf.program_mut("exit_capture").unwrap().try_into()?;
        exit.load("acct_process", &btf)?;
        exit.attach()?;

        let program: &mut Lsm = self.ebpf.program_mut("creds_capture").unwrap().try_into()?;
        program.load("bprm_committing_creds", &btf)?;
        program.attach()?;
        Ok(())
    }
}

// TODO: We need to have proto config descriptions

/// Yaml provided user config
struct ProcmonConfig {
    pub expose_events: bool,
    pub filter: Option<ProcessFilter>,
}

pub enum ProcessFilter {
    AllowList(ProcessFilterConfig),
    DenyList(ProcessFilterConfig),
}
/// Config to filter Process events
#[derive(Default)]
pub struct ProcessFilterConfig {
    pub uid: Vec<u32>,
    pub euid: Vec<u32>,
    pub auid: Vec<u32>,
    pub binary_name: Vec<String>,
    pub binary_path: Vec<String>,
    pub binary_prefix: Vec<String>,
}

impl ProcmonConfig {
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
            Ok(ProcmonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: Some(ProcessFilter::AllowList(ProcessFilterConfig::new(filter)?)),
            })
        } else if let Some(filter) = yaml.get(&Yaml::from_str("process_deny_list")) {
            Ok(ProcmonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: Some(ProcessFilter::DenyList(ProcessFilterConfig::new(filter)?)),
            })
        } else {
            Ok(ProcmonConfig {
                expose_events: expose_events.as_bool().unwrap_or(false),
                filter: None,
            })
        }
    }
}

impl ProcessFilterConfig {
    pub fn new(yaml: &Yaml) -> Result<Self, anyhow::Error> {
        let mut config = ProcessFilterConfig::default();
        let Some(yaml) = yaml.as_hash() else {
            anyhow::bail!("yaml must be a hash")
        };
        if let Some(uid) = yaml.get(&Yaml::from_str("uid")) {
            let Some(uid) = uid.as_vec() else {
                anyhow::bail!("uid must be a vec")
            };
            config.uid = uid
                .iter()
                .filter_map(|e| e.as_i64())
                .map(|e| e as u32)
                .collect();
        }
        if let Some(euid) = yaml.get(&Yaml::from_str("euid")) {
            let Some(euid) = euid.as_vec() else {
                anyhow::bail!("euid must be a vec")
            };
            config.euid = euid
                .iter()
                .filter_map(|e| e.as_i64())
                .map(|e| e as u32)
                .collect();
        }
        if let Some(auid) = yaml.get(&Yaml::from_str("auid")) {
            let Some(auid) = auid.as_vec() else {
                anyhow::bail!("auid must be a vec")
            };
            config.auid = auid
                .iter()
                .filter_map(|e| e.as_i64())
                .map(|e| e as u32)
                .collect();
        }
        if let Some(binary) = yaml.get(&Yaml::from_str("binary")) {
            let Some(binary) = binary.as_hash() else {
                anyhow::bail!("binary must be a hash")
            };
            if let Some(name) = binary.get(&Yaml::from_str("name")) {
                let Some(name) = name.as_vec() else {
                    anyhow::bail!("name must be a vec")
                };
                config.binary_name = name
                    .iter()
                    .filter_map(|e| e.clone().into_string())
                    .collect();
            }
            if let Some(path) = binary.get(&Yaml::from_str("path")) {
                let Some(path) = path.as_vec() else {
                    anyhow::bail!("path must be a vec")
                };
                config.binary_path = path
                    .iter()
                    .filter_map(|e| e.clone().into_string())
                    .collect();
            }
            if let Some(prefix) = binary.get(&Yaml::from_str("prefix")) {
                let Some(prefix) = prefix.as_vec() else {
                    anyhow::bail!("prefix must be a vec")
                };
                config.binary_prefix = prefix
                    .iter()
                    .filter_map(|e| e.clone().into_string())
                    .collect();
            }
        }
        Ok(config)
    }
}

/// ProcMon Filter map names
const FILTER_UID_MAP_NAME: &str = "PROCMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "PROCMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "PROCMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "PROCMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "PROCMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "PROCMON_FILTER_BINPREFIX_MAP";
