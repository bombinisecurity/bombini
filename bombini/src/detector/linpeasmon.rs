//! LinPEAS detector

use aya::maps::array::Array;
use aya::maps::hash_map::HashMap;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use bombini_common::config::linpeasmon::{LINPEASMON_FULLNAME_SIZE, LinPEASMonKernelConfig};
use bombini_common::config::rule::PathPrefixMapKey;
use bombini_common::constants::MAX_FILE_PREFIX;

use std::{path::Path, sync::Arc};

use procfs::sys::kernel::Version;

use crate::proto::config::LinPeasMonConfig;

use super::Detector;

pub struct LinPEASMon {
    ebpf: Ebpf,
    config: LinPEASMonKernelConfig,
    signature_names: Vec<String>,
    signature_prefixes: Vec<String>,
}

impl LinPEASMon {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        config: Arc<LinPeasMonConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let kernel_config = LinPEASMonKernelConfig {
            behavioral_enabled: config.behavioral_enabled,
            signature_enabled: config.signature_enabled,
            threshold: config.threshold as u8,
            window_ns: config.window_seconds.saturating_mul(1_000_000_000),
        };

        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.map_pin_path(maps_pin_path.as_ref());
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;

        Ok(LinPEASMon {
            ebpf,
            config: kernel_config,
            signature_names: config.signature_names.clone(),
            signature_prefixes: config.signature_prefixes.clone(),
        })
    }
}

impl Detector for LinPEASMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config_map: Array<_, LinPEASMonKernelConfig> =
            Array::try_from(self.ebpf.map_mut("LINPEASMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, self.config, 0);

        let mut sig_names: HashMap<_, [u8; LINPEASMON_FULLNAME_SIZE], u8> =
            HashMap::try_from(self.ebpf.map_mut("LINPEASMON_SIG_NAMES").unwrap())?;
        for (idx, name) in self.signature_names.iter().enumerate() {
            let mut k = [0; LINPEASMON_FULLNAME_SIZE];
            let k_str = name.as_bytes();
            let len = k_str.len();
            if len < LINPEASMON_FULLNAME_SIZE {
                k[..len].clone_from_slice(k_str);
            } else {
                k.clone_from_slice(&k_str[..LINPEASMON_FULLNAME_SIZE]);
            }
            sig_names.insert(k, (idx as u8).saturating_add(1), 0)?;
        }

        let mut sig_prefixes: LpmTrie<_, PathPrefixMapKey, u8> =
            LpmTrie::try_from(self.ebpf.map_mut("LINPEASMON_SIG_PREFIXES").unwrap())?;
        for (idx, prefix) in self.signature_prefixes.iter().enumerate() {
            let mut data = PathPrefixMapKey {
                rule_idx: 0,
                path_prefix: [0; MAX_FILE_PREFIX],
            };
            let k_str = prefix.as_bytes();
            let len = k_str.len();
            let copy = if len < MAX_FILE_PREFIX {
                len
            } else {
                MAX_FILE_PREFIX
            };
            data.path_prefix[..copy].clone_from_slice(&k_str[..copy]);
            let key = Key::new((copy as u32).saturating_mul(8), data);
            sig_prefixes.insert(&key, (idx as u8).saturating_add(1), 0)?;
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

        if self.config.signature_enabled {
            let file_open: &mut Lsm = self
                .ebpf
                .program_mut("file_open_capture")
                .unwrap()
                .try_into()?;
            file_open.load("file_open", &btf)?;
            file_open.attach()?;
        }
        Ok(())
    }

    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 8, 0)
    }
}
