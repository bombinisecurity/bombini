// Detect process execution life cycle

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::{BtfTracePoint, Lsm};
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use procfs::process;

use std::path::Path;

use bombini_common::{
    config::procmon::{Config, CredFilterMask, ProcessFilterMask},
    constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX},
    event::process::{Capabilities, ProcInfo},
};

use crate::{
    config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME},
    init_process_filter_maps,
    proto::config::ProcMonConfig,
    resize_process_filter_maps,
};

use super::Detector;

pub struct ProcMon {
    /// aya::Ebpf object
    ebpf: Ebpf,
    /// User supplied config
    config: ProcMonConfig,
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
        let config: ProcMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
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
        resize_cred_filter_maps(&config, ebpf_loader_ref);

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(ProcMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            expose_events: false,
            filter_mask: ProcessFilterMask::empty(),
            cred_mask: [CredFilterMask::empty(); 3],
            deny_list: false,
            ima_hash: false,
        };
        config.expose_events = self.config.expose_events;
        config.ima_hash = self.config.ima_hash.unwrap_or_default();
        if let Some(filter) = &self.config.process_filter {
            config.filter_mask = init_process_filter_maps!(filter, &mut self.ebpf);
            config.deny_list = filter.deny_list;
        }
        init_cred_filter_maps(&mut config, &self.config, &mut self.ebpf)?;
        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("PROCMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);

        let current_processes = process::all_processes().unwrap();
        let mut proc_map: HashMap<_, u32, ProcInfo> =
            HashMap::try_from(self.ebpf.map_mut("PROCMON_PROC_MAP").unwrap())?;
        current_processes
            .filter_map(|p| p.ok())
            .filter(|p| p.is_alive())
            .filter_map(|p| ProcInfo::from_procfs(&p))
            .for_each(|p| {
                let _ = proc_map.insert(p.pid, p, 0);
            });

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

        let fork: &mut BtfTracePoint = self.ebpf.program_mut("fork_capture").unwrap().try_into()?;
        fork.load("sched_process_fork", &btf)?;
        fork.attach()?;

        let exit: &mut BtfTracePoint = self.ebpf.program_mut("exit_capture").unwrap().try_into()?;
        exit.load("sched_process_exit", &btf)?;
        exit.attach()?;

        let program: &mut Lsm = self.ebpf.program_mut("creds_capture").unwrap().try_into()?;
        program.load("bprm_committing_creds", &btf)?;
        program.attach()?;

        if let Some(ref setuid_cfg) = self.config.setuid {
            if setuid_cfg.enabled {
                let setuid: &mut Lsm = self
                    .ebpf
                    .program_mut("setuid_capture")
                    .unwrap()
                    .try_into()?;
                setuid.load("task_fix_setuid", &btf)?;
                setuid.attach()?;
            }
        }
        if let Some(ref capset_cfg) = self.config.capset {
            if capset_cfg.enabled {
                let capset: &mut Lsm = self
                    .ebpf
                    .program_mut("capset_capture")
                    .unwrap()
                    .try_into()?;
                capset.load("capset", &btf)?;
                capset.attach()?;
            }
        }
        if let Some(ref prctl_cfg) = self.config.prctl {
            if prctl_cfg.enabled {
                let prctl: &mut Lsm = self
                    .ebpf
                    .program_mut("task_prctl_capture")
                    .unwrap()
                    .try_into()?;
                prctl.load("task_prctl", &btf)?;
                prctl.attach()?;
            }
        }
        if let Some(ref create_user_ns_cfg) = self.config.create_user_ns {
            if create_user_ns_cfg.enabled {
                let create_user_ns: &mut Lsm = self
                    .ebpf
                    .program_mut("create_user_ns_capture")
                    .unwrap()
                    .try_into()?;
                create_user_ns.load("userns_create", &btf)?;
                create_user_ns.attach()?;
            }
        }
        if let Some(ref ptrace_cfg) = self.config.ptrace_access_check {
            if ptrace_cfg.enabled {
                let ptrace: &mut Lsm = self
                    .ebpf
                    .program_mut("ptrace_access_check_capture")
                    .unwrap()
                    .try_into()?;
                ptrace.load("ptrace_access_check", &btf)?;
                ptrace.attach()?;
            }
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! resize_process_filter_maps {
    ($filter_config:expr, $ebpf_loader_ref:expr) => {
        if $filter_config.uid.len() > 1 {
            $ebpf_loader_ref = $ebpf_loader_ref
                .set_max_entries(FILTER_UID_MAP_NAME, $filter_config.uid.len() as u32);
        }
        if $filter_config.euid.len() > 1 {
            $ebpf_loader_ref = $ebpf_loader_ref
                .set_max_entries(FILTER_EUID_MAP_NAME, $filter_config.euid.len() as u32);
        }
        if $filter_config.auid.len() > 1 {
            $ebpf_loader_ref = $ebpf_loader_ref
                .set_max_entries(FILTER_AUID_MAP_NAME, $filter_config.auid.len() as u32);
        }
        if let Some(binary) = $filter_config.binary.as_ref() {
            if binary.name.len() > 1 {
                $ebpf_loader_ref = $ebpf_loader_ref
                    .set_max_entries(FILTER_BINNAME_MAP_NAME, binary.name.len() as u32);
            }
            if binary.path.len() > 1 {
                $ebpf_loader_ref = $ebpf_loader_ref
                    .set_max_entries(FILTER_BINPATH_MAP_NAME, binary.path.len() as u32);
            }
            if binary.prefix.len() > 1 {
                $ebpf_loader_ref = $ebpf_loader_ref
                    .set_max_entries(FILTER_BINPREFIX_MAP_NAME, binary.prefix.len() as u32);
            }
        }
    };
}

#[macro_export]
macro_rules! init_process_filter_maps {
    ($filter_config:expr, $ebpf:expr) => {{
        let mut filter_mask = ProcessFilterMask::empty();
        if !$filter_config.uid.is_empty() {
            let mut uid_map: HashMap<_, u32, u8> =
                HashMap::try_from($ebpf.map_mut(FILTER_UID_MAP_NAME).unwrap())?;
            for v in $filter_config.uid.iter() {
                let _ = uid_map.insert(v, 0, 0);
            }
            filter_mask |= ProcessFilterMask::UID;
        }
        if !$filter_config.euid.is_empty() {
            let mut euid_map: HashMap<_, u32, u8> =
                HashMap::try_from($ebpf.map_mut(FILTER_EUID_MAP_NAME).unwrap())?;
            for v in $filter_config.euid.iter() {
                let _ = euid_map.insert(v, 0, 0);
            }
            filter_mask |= ProcessFilterMask::EUID;
        }
        if !$filter_config.auid.is_empty() {
            let mut auid_map: HashMap<_, u32, u8> =
                HashMap::try_from($ebpf.map_mut(FILTER_AUID_MAP_NAME).unwrap())?;
            for v in $filter_config.auid.iter() {
                let _ = auid_map.insert(v, 0, 0);
            }
            filter_mask |= ProcessFilterMask::AUID;
        }
        if let Some(binary) = $filter_config.binary.as_ref() {
            if !binary.name.is_empty() {
                let mut bname_map: HashMap<_, [u8; MAX_FILENAME_SIZE], u8> =
                    HashMap::try_from($ebpf.map_mut(FILTER_BINNAME_MAP_NAME).unwrap())?;
                for name in binary.name.iter() {
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
                filter_mask |= ProcessFilterMask::BINARY_NAME;
            }
            if !binary.path.is_empty() {
                let mut bpath_map: HashMap<_, [u8; MAX_FILE_PATH], u8> =
                    HashMap::try_from($ebpf.map_mut(FILTER_BINPATH_MAP_NAME).unwrap())?;
                for path in binary.path.iter() {
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
                filter_mask |= ProcessFilterMask::BINARY_PATH;
            }
            if !binary.prefix.is_empty() {
                let mut bprefix_map: LpmTrie<_, [u8; MAX_FILE_PREFIX], u8> =
                    LpmTrie::try_from($ebpf.map_mut(FILTER_BINPREFIX_MAP_NAME).unwrap())?;
                for prefix in binary.prefix.iter() {
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
                filter_mask |= ProcessFilterMask::BINARY_PATH_PREFIX;
            }
        }
        filter_mask
    }};
}

#[inline]
fn resize_cred_filter_maps(config: &ProcMonConfig, loader: &mut EbpfLoader) {
    if let Some(ref capset_cfg) = config.capset {
        if let Some(ref cred_filter) = capset_cfg.cred_filter {
            if let Some(ref cap_filter) = cred_filter.cap_filter {
                if cap_filter.effective.len() > 1 {
                    loader.set_max_entries(
                        FILTER_CAPSET_ECAP_MAP_NAME,
                        cap_filter.effective.len() as u32,
                    );
                }
            }
        }
    }
    if let Some(ref setuid_cfg) = config.setuid {
        if let Some(ref cred_filter) = setuid_cfg.cred_filter {
            if let Some(ref uid_filter) = cred_filter.uid_filter {
                if uid_filter.euid.len() > 1 {
                    loader
                        .set_max_entries(FILTER_SETUID_EUID_MAP_NAME, uid_filter.euid.len() as u32);
                }
            }
        }
    }
    if let Some(ref userns_cfg) = config.create_user_ns {
        if let Some(ref cred_filter) = userns_cfg.cred_filter {
            if let Some(ref uid_filter) = cred_filter.uid_filter {
                if uid_filter.euid.len() > 1 {
                    loader
                        .set_max_entries(FILTER_USERNS_ECAP_MAP_NAME, uid_filter.euid.len() as u32);
                }
            }
            if let Some(ref cap_filter) = cred_filter.cap_filter {
                if cap_filter.effective.len() > 1 {
                    loader.set_max_entries(
                        FILTER_USERNS_ECAP_MAP_NAME,
                        cap_filter.effective.len() as u32,
                    );
                }
            }
        }
    }
}

macro_rules! init_uid_filter_map {
    ($uid_list:expr, $ebpf:expr, $map_name:expr) => {{
        let mut uid_map: HashMap<_, u32, u8> =
            HashMap::try_from($ebpf.map_mut($map_name).unwrap())?;
        for v in $uid_list.iter() {
            let _ = uid_map.insert(v, 0, 0);
        }
    }};
}

use std::str::FromStr;

macro_rules! init_cap_filter_map {
    ($cap_list:expr, $ebpf:expr, $map_name:expr) => {{
        let mut cap_map: Array<_, u64> = Array::try_from($ebpf.map_mut($map_name).unwrap())?;
        for (i, v) in $cap_list.iter().enumerate() {
            if *v == "ANY" {
                let _ = cap_map.set(i as u32, 1 << 63, 0);
                continue;
            }
            if let Ok(cap) = Capabilities::from_str(v) {
                let _ = cap_map.set(i as u32, cap.bits(), 0);
            }
        }
    }};
}

#[inline]
fn init_cred_filter_maps(
    ebpf_config: &mut Config,
    config: &ProcMonConfig,
    ebpf: &mut Ebpf,
) -> Result<(), EbpfError> {
    if let Some(ref setuid_cfg) = config.setuid {
        if let Some(ref cred_filter) = setuid_cfg.cred_filter {
            if let Some(ref uid_filter) = cred_filter.uid_filter {
                if !uid_filter.euid.is_empty() {
                    init_uid_filter_map!(&uid_filter.euid, ebpf, FILTER_SETUID_EUID_MAP_NAME);
                    ebpf_config.cred_mask[0] |= CredFilterMask::EUID;
                }
            }
        }
    }
    if let Some(ref capset_cfg) = config.capset {
        if let Some(ref cred_filter) = capset_cfg.cred_filter {
            if let Some(ref cap_filter) = cred_filter.cap_filter {
                if !cap_filter.effective.is_empty() {
                    init_cap_filter_map!(&cap_filter.effective, ebpf, FILTER_CAPSET_ECAP_MAP_NAME);
                    let deny = cap_filter.deny_list.unwrap_or(false);
                    if deny {
                        ebpf_config.cred_mask[1] |= CredFilterMask::E_CAPS_DENY_LIST;
                    } else {
                        ebpf_config.cred_mask[1] |= CredFilterMask::E_CAPS;
                    }
                }
            }
        }
    }
    if let Some(ref userns_cfg) = config.create_user_ns {
        if let Some(ref cred_filter) = userns_cfg.cred_filter {
            if let Some(ref uid_filter) = cred_filter.uid_filter {
                if !uid_filter.euid.is_empty() {
                    init_uid_filter_map!(&uid_filter.euid, ebpf, FILTER_USERNS_EUID_MAP_NAME);
                    ebpf_config.cred_mask[2] |= CredFilterMask::EUID;
                }
            }
            if let Some(ref cap_filter) = cred_filter.cap_filter {
                if !cap_filter.effective.is_empty() {
                    init_cap_filter_map!(&cap_filter.effective, ebpf, FILTER_USERNS_ECAP_MAP_NAME);
                    let deny = cap_filter.deny_list.unwrap_or(false);
                    if deny {
                        ebpf_config.cred_mask[2] |= CredFilterMask::E_CAPS_DENY_LIST;
                    } else {
                        ebpf_config.cred_mask[2] |= CredFilterMask::E_CAPS;
                    }
                }
            }
        }
    }
    Ok(())
}

// ProcMon Filter map names
const FILTER_UID_MAP_NAME: &str = "PROCMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "PROCMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "PROCMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "PROCMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "PROCMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "PROCMON_FILTER_BINPREFIX_MAP";

// Cred filter map names
const FILTER_SETUID_EUID_MAP_NAME: &str = "PROCMON_FILTER_SETUID_EUID_MAP";

const FILTER_CAPSET_ECAP_MAP_NAME: &str = "PROCMON_FILTER_CAPSET_ECAP_MAP";

const FILTER_USERNS_ECAP_MAP_NAME: &str = "PROCMON_FILTER_USERNS_ECAP_MAP";

const FILTER_USERNS_EUID_MAP_NAME: &str = "PROCMON_FILTER_USERNS_EUID_MAP";
