//! Bombini agent configuration

use anyhow::anyhow;
use log::warn;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{
    options::Options,
    proto::config::{FileMonConfig, GtfoBinsConfig, NetMonConfig, ProcMonConfig},
};

/// Unified Detector's config representation
#[derive(Debug)]
pub enum DetectorConfig {
    ProcMon(Arc<ProcMonConfig>),
    FileMon(Arc<FileMonConfig>),
    NetMon(Arc<NetMonConfig>),
    IOUringMon,
    GTFOBins(Arc<GtfoBinsConfig>),
}

/// Configuration for agent and all detectors
#[derive(Debug, Default)]
pub struct Config {
    /// Agent Options
    pub options: Options,
    /// Detector Configs
    pub detector_configs: HashMap<String, DetectorConfig>,
}

impl Config {
    /// Construct config using parsed options
    pub fn new(options: Options) -> Self {
        Config {
            options,
            detector_configs: HashMap::new(),
        }
    }

    /// Parse YAML configuration files for detectors
    pub fn parse_configs(&mut self) -> Result<(), anyhow::Error> {
        let Some(ref mut names) = self.options.detectors else {
            return Err(anyhow!("Detector list must exists"));
        };
        if names.is_empty() || !names.contains(&"procmon".to_string()) {
            warn!("procmon is not found in config.yaml or options. It will be forced loaded.");
            names.push("procmon".to_string());
        }
        let mut config_path = PathBuf::from(&self.options.config_dir);
        for name in names.iter().map(|e| e.as_str()) {
            config_path.push(name.to_owned() + ".yaml");
            let yaml_config = std::fs::read_to_string(&config_path)?;
            let config = match name {
                "procmon" => {
                    let config: ProcMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
                    DetectorConfig::ProcMon(Arc::new(config))
                }
                "filemon" => {
                    let config: FileMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
                    DetectorConfig::FileMon(Arc::new(config))
                }
                "netmon" => {
                    let config: NetMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
                    DetectorConfig::NetMon(Arc::new(config))
                }
                "io_uringmon" => DetectorConfig::IOUringMon,
                "gtfobins" => {
                    let config: GtfoBinsConfig = serde_yml::from_str(yaml_config.as_ref())?;
                    DetectorConfig::GTFOBins(Arc::new(config))
                }
                _ => {
                    return Err(anyhow!("{} unknown detector", name));
                }
            };
            self.detector_configs.insert(name.to_string(), config);
            config_path.pop();
        }

        Ok(())
    }
}
