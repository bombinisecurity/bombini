//! GTFOBins detector

use aya::maps::hash_map::HashMap;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError};

use yaml_rust2::{Yaml, YamlLoader};

use bombini_common::constants::MAX_FILENAME_SIZE;

use std::path::Path;

use super::{load_ebpf_obj, Detector};

pub struct GTFOBinsDetector {
    ebpf: Ebpf,
    config: Option<GTFOBinsConfig>,
}

struct GTFOBinsConfig {
    /// Entry values for GTFOBins map
    gtfobins_entries: Vec<([u8; MAX_FILENAME_SIZE], u32)>,
}

impl Detector for GTFOBinsDetector {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let ebpf = load_ebpf_obj(obj_path).await?;
        if let Some(yaml_config) = yaml_config {
            // Get config
            let mut config = GTFOBinsConfig {
                gtfobins_entries: Vec::new(),
            };

            let docs = YamlLoader::load_from_str(yaml_config.as_ref())?;
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
                    let mut k = [0; MAX_FILENAME_SIZE];
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
            let mut file_names: HashMap<_, [u8; MAX_FILENAME_SIZE], u32> =
                HashMap::try_from(self.ebpf.map_mut("GTFOBINS_NAME_MAP").unwrap())?;
            for (k, v) in config.gtfobins_entries.iter() {
                file_names.insert(k, v, 0)?;
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
