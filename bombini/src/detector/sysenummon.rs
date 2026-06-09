//! SysEnumMon detector

use aya::maps::array::Array;
use aya::maps::hash_map::HashMap as EbpfHashMap;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::{BtfTracePoint, Lsm};
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use bombini_common::config::sysenummon::SysEnumMonKernelConfig;
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, PAGE_SIZE};
use bombini_common::event::sysenum::SYSENUMMON_CHAIN_MAX;
use std::{path::Path, sync::Arc};

use procfs::sys::kernel::Version;

use crate::proto::config::SysEnumMonConfig;

use super::Detector;

pub struct SysEnumMon {
    ebpf: Ebpf,
    config: SysEnumMonKernelConfig,
    names: Vec<([u8; MAX_FILENAME_SIZE], u8)>,
    paths: Vec<([u8; MAX_FILE_PATH], u8)>,
    path_prefixes: Vec<(u32, [u8; MAX_FILE_PREFIX], u8)>,
}

impl SysEnumMon {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        config: Arc<SysEnumMonConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        if config.chain_size < 1 || config.chain_size as usize > SYSENUMMON_CHAIN_MAX {
            return Err(anyhow::anyhow!(
                "sysenummon: chain_size must be in [1, {}], got {}",
                SYSENUMMON_CHAIN_MAX,
                config.chain_size
            ));
        }
        let kernel_config = SysEnumMonKernelConfig {
            chain_size: config.chain_size as u8,
            window_ns: config.window_size_sec.saturating_mul(1_000_000_000),
        };

        let mut watch_idx: u8 = 0;

        let mut names = Vec::new();
        if let Some(ref bprm) = config.bprm_check {
            for s in &bprm.name {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_FILENAME_SIZE);
                let mut name = [0u8; MAX_FILENAME_SIZE];
                name[..len].copy_from_slice(&bytes[..len]);
                names.push((name, watch_idx));
                watch_idx += 1;
            }
        }

        let mut paths = Vec::new();
        let mut path_prefixes = Vec::new();
        if let Some(ref open) = config.file_open {
            for s in &open.path {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_FILE_PATH);
                let mut path = [0u8; MAX_FILE_PATH];
                path[..len].copy_from_slice(&bytes[..len]);
                paths.push((path, watch_idx));
                watch_idx += 1;
            }
            for s in &open.path_prefix {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_FILE_PREFIX);
                let mut path_prefix = [0u8; MAX_FILE_PREFIX];
                path_prefix[..len].copy_from_slice(&bytes[..len]);
                path_prefixes.push(((len * 8) as u32, path_prefix, watch_idx));
                watch_idx += 1;
            }
        }

        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.map_pin_path(maps_pin_path.as_ref());
        if !names.is_empty() {
            ebpf_loader_ref.set_max_entries("SYSENUMMON_NAME_MAP", names.len() as u32);
        }
        if !paths.is_empty() {
            ebpf_loader_ref.set_max_entries("SYSENUMMON_PATH_MAP", paths.len() as u32);
        }
        if !path_prefixes.is_empty() {
            ebpf_loader_ref
                .set_max_entries("SYSENUMMON_PATH_PREFIX_MAP", path_prefixes.len() as u32);
        }
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(SysEnumMon {
            ebpf,
            config: kernel_config,
            names,
            paths,
            path_prefixes,
        })
    }
}

impl Detector for SysEnumMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config_map: Array<_, SysEnumMonKernelConfig> =
            Array::try_from(self.ebpf.map_mut("SYSENUMMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, self.config, 0);

        let mut name_map: EbpfHashMap<_, [u8; MAX_FILENAME_SIZE], u8> =
            EbpfHashMap::try_from(self.ebpf.map_mut("SYSENUMMON_NAME_MAP").unwrap())?;
        // Populate basename watch list: bprm_check lookups read from here.
        for (key, watch_idx) in self.names.iter() {
            let _ = name_map.insert(key, watch_idx, 0);
        }

        let mut path_map: EbpfHashMap<_, [u8; MAX_FILE_PATH], u8> =
            EbpfHashMap::try_from(self.ebpf.map_mut("SYSENUMMON_PATH_MAP").unwrap())?;
        // Populate exact-path watch list: file_open lookups read from here.
        for (key, watch_idx) in self.paths.iter() {
            let _ = path_map.insert(key, watch_idx, 0);
        }

        let mut prefix_map: LpmTrie<_, [u8; MAX_FILE_PREFIX], u8> =
            LpmTrie::try_from(self.ebpf.map_mut("SYSENUMMON_PATH_PREFIX_MAP").unwrap())?;
        // Populate prefix watch list: file_open does an LPM lookup here.
        for (prefix_len, key, watch_idx) in self.path_prefixes.iter() {
            let map_key = Key::new(*prefix_len, *key);
            let _ = prefix_map.insert(&map_key, watch_idx, 0);
        }
        let mut zero_map: Array<_, [u8; PAGE_SIZE]> =
            Array::try_from(self.ebpf.map_mut("ZERO_MAP").unwrap())?;
        let _ = zero_map.set(0, [0; PAGE_SIZE], 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let bprm: &mut Lsm = self
            .ebpf
            .program_mut("sysmon_bprm_check")
            .unwrap()
            .try_into()?;
        bprm.load("bprm_check_security", &btf)?;
        bprm.attach()?;

        let open: &mut Lsm = self
            .ebpf
            .program_mut("sysmon_file_open")
            .unwrap()
            .try_into()?;
        open.load("file_open", &btf)?;
        open.attach()?;

        let exit: &mut BtfTracePoint = self
            .ebpf
            .program_mut("sysmon_process_exit")
            .unwrap()
            .try_into()?;
        exit.load("sched_process_exit", &btf)?;
        exit.attach()?;
        Ok(())
    }

    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 2, 0)
    }
}
