//! GTFOBins detector

use aya::maps::hash_map::HashMap;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError};

use bombini_common::constants::MAX_FILENAME_SIZE;

use std::path::Path;

use crate::proto::config::GtfoBinsConfig;

use super::{load_ebpf_obj, Detector};

pub struct GTFOBinsDetector {
    ebpf: Ebpf,
    config: GtfoBinsConfig,
}

impl Detector for GTFOBinsDetector {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let Some(yaml_config) = yaml_config else {
            anyhow::bail!("Config for GTFOBins detector must be provided");
        };
        let ebpf = load_ebpf_obj(obj_path).await?;

        let config: GtfoBinsConfig = serde_yml::from_str(yaml_config.as_ref())?;
        Ok(GTFOBinsDetector { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut file_names: HashMap<_, [u8; MAX_FILENAME_SIZE], u32> =
            HashMap::try_from(self.ebpf.map_mut("GTFOBINS_NAME_MAP").unwrap())?;
        for bin in self.config.gtfobins.iter() {
            let mut k = [0; MAX_FILENAME_SIZE];
            let k_str = bin.as_bytes();
            let len = k_str.len();
            if len < MAX_FILENAME_SIZE {
                k[..len].clone_from_slice(k_str);
            } else {
                k.clone_from_slice(&k_str[..MAX_FILENAME_SIZE]);
            }
            file_names.insert(k, self.config.enforce as u32, 0)?;
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
