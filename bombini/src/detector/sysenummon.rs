//! SysEnumMon detector

use aya::maps::array::Array;
use aya::maps::hash_map::HashMap as EbpfHashMap;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use bombini_common::config::rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey};
use bombini_common::config::sysenummon::{SYSENUMMON_BITS, SysEnumMonKernelConfig};
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};

use std::{path::Path, sync::Arc};

use procfs::sys::kernel::Version;

use crate::proto::config::SysEnumMonConfig;

use super::Detector;

pub struct SysEnumMon {
    ebpf: Ebpf,
    config: SysEnumMonKernelConfig,
    names: Vec<(FileNameMapKey, u8)>,
    paths: Vec<(PathMapKey, u8)>,
    path_prefixes: Vec<(u32, PathPrefixMapKey, u8)>,
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
        let kernel_config = SysEnumMonKernelConfig {
            chain_size: config.chain_size.min(u8::MAX as u32) as u8,
            window_ns: config.window_size_sec.saturating_mul(1_000_000_000),
        };

        let mut next_bit: u32 = 0;
        let take_bit = |bit: &mut u32| -> Result<u8, anyhow::Error> {
            if (*bit as usize) >= SYSENUMMON_BITS {
                anyhow::bail!(
                    "sysenummon watch-list exceeds {} unique entries",
                    SYSENUMMON_BITS
                );
            }
            let b = *bit as u8;
            *bit += 1;
            Ok(b)
        };

        let mut names = Vec::new();
        if let Some(ref bprm) = config.bprm_check {
            for s in &bprm.name {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_FILENAME_SIZE);
                let mut name = [0u8; MAX_FILENAME_SIZE];
                name[..len].copy_from_slice(&bytes[..len]);
                names.push((
                    FileNameMapKey { rule_idx: 0, name },
                    take_bit(&mut next_bit)?,
                ));
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
                paths.push((PathMapKey { rule_idx: 0, path }, take_bit(&mut next_bit)?));
            }
            for s in &open.path_prefix {
                let bytes = s.as_bytes();
                let len = bytes.len().min(MAX_FILE_PREFIX);
                let mut path_prefix = [0u8; MAX_FILE_PREFIX];
                path_prefix[..len].copy_from_slice(&bytes[..len]);
                path_prefixes.push((
                    (len * 8) as u32,
                    PathPrefixMapKey {
                        rule_idx: 0,
                        path_prefix,
                    },
                    take_bit(&mut next_bit)?,
                ));
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

        let mut name_map: EbpfHashMap<_, FileNameMapKey, u8> =
            EbpfHashMap::try_from(self.ebpf.map_mut("SYSENUMMON_NAME_MAP").unwrap())?;
        for (key, bit) in self.names.iter() {
            let _ = name_map.insert(key, bit, 0);
        }

        let mut path_map: EbpfHashMap<_, PathMapKey, u8> =
            EbpfHashMap::try_from(self.ebpf.map_mut("SYSENUMMON_PATH_MAP").unwrap())?;
        for (key, bit) in self.paths.iter() {
            let _ = path_map.insert(key, bit, 0);
        }

        let mut prefix_map: LpmTrie<_, PathPrefixMapKey, u8> =
            LpmTrie::try_from(self.ebpf.map_mut("SYSENUMMON_PATH_PREFIX_MAP").unwrap())?;
        for (prefix_len, key, bit) in self.path_prefixes.iter() {
            let map_key = Key::new(*prefix_len, *key);
            let _ = prefix_map.insert(&map_key, bit, 0);
        }
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let bprm: &mut Lsm = self
            .ebpf
            .program_mut("bprm_check_capture")
            .unwrap()
            .try_into()?;
        bprm.load("bprm_check_security", &btf)?;
        bprm.attach()?;

        let open: &mut Lsm = self
            .ebpf
            .program_mut("file_open_capture")
            .unwrap()
            .try_into()?;
        open.load("file_open", &btf)?;
        open.attach()?;
        Ok(())
    }

    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 8, 0)
    }
}
