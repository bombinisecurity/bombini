//! GTFOBins detector

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError};

use procfs::sys::kernel::Version;
use yaml_rust2::{Yaml, YamlLoader};

use bombini_common::config::gtfobins::GTFOBinsKey;
use bombini_common::event::process::MAX_FILENAME_SIZE;

use std::path::Path;

use super::{load_ebpf_obj, Detector};

pub struct GTFOBinsDetector {
    ebpf: Ebpf,
    config: Option<GTFOBinsConfig>,
}

struct GTFOBinsConfig {
    /// Entry values for GTFOBins map
    gtfobins_entries: Vec<(GTFOBinsKey, u32)>,
}

impl Detector for GTFOBinsDetector {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 11, 0)
    }

    async fn new<U: AsRef<Path>>(
        obj_path: U,
        config_path: Option<U>,
    ) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        if let Some(config_path) = config_path {
            // Get config
            let mut config = GTFOBinsConfig {
                gtfobins_entries: Vec::new(),
            };

            let s = std::fs::read_to_string(config_path.as_ref())?;
            let docs = YamlLoader::load_from_str(&s)?;
            let Some(doc) = docs[0].as_hash() else {
                anyhow::bail!("GTFObins config must be a Hash")
            };

            let enfroce = if let Some(value) = doc.get(&Yaml::from_str("enforce")) {
                let Some(value) = value.as_bool() else {
                    anyhow::bail!("enforce value must be a bool")
                };
                if value {
                    1
                } else {
                    0
                }
            } else {
                0
            };

            if let Some(entries) = doc.get(&Yaml::from_str("gtfobins")) {
                let Some(entries) = entries.as_vec() else {
                    anyhow::bail!("GTFObins binaries name must be a vec")
                };
                for entry in entries {
                    let mut k: GTFOBinsKey = [0; MAX_FILENAME_SIZE];
                    let Some(k_str) = entry.as_str() else {
                        continue;
                    };
                    let k_str = k_str.as_bytes();
                    let len = k_str.len();
                    if len < MAX_FILENAME_SIZE {
                        k[..len].clone_from_slice(k_str);
                    } else {
                        k.clone_from_slice(&k_str[..MAX_FILENAME_SIZE]);
                    }

                    config.gtfobins_entries.push((k, enfroce));
                }
            }
            Ok(GTFOBinsDetector {
                ebpf,
                config: Some(config),
            })
        } else {
            Ok(GTFOBinsDetector { ebpf, config: None })
        }
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(config) = &self.config {
            let mut file_names: LpmTrie<_, GTFOBinsKey, u32> =
                LpmTrie::try_from(self.ebpf.map_mut("GTFOBINS").unwrap())?;
            for (k, v) in config.gtfobins_entries.iter() {
                let key = Key::new((MAX_FILENAME_SIZE * 8) as u32, *k);
                file_names.insert(&key, v, 0)?;
            }
        }
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let program: &mut Lsm = self
            .ebpf
            .program_mut("gtfobins_detect")
            .unwrap()
            .try_into()?;
        let btf = Btf::from_sys_fs()?;
        program.load("bprm_check_security", &btf)?;
        program.attach()?;
        Ok(())
    }
}
