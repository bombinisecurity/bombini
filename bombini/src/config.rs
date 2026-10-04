//! Bombini agent configuration

use anyhow::anyhow;
use log::warn;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{
    options::Options,
    proto::config::{
        FileMonConfig, KernelMonConfig, NetMonConfig, ProcMonConfig, SysEnumMonConfig,
    },
};

/// Unified Detector's config representation
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum DetectorConfig {
    ProcMon(Arc<ProcMonConfig>),
    FileMon(Arc<FileMonConfig>),
    NetMon(Arc<NetMonConfig>),
    KernelMon(Arc<KernelMonConfig>),
    IOUringMon,
    SysEnumMon(Arc<SysEnumMonConfig>),
}

impl DetectorConfig {
    /// Checks that detector rules compile without loading eBPF programs
    #[cfg(test)]
    pub fn check_rules(&self) -> Result<(), anyhow::Error> {
        match self {
            DetectorConfig::ProcMon(config) => crate::detector::procmon::check_rules(config),
            DetectorConfig::FileMon(config) => crate::detector::filemon::check_rules(config),
            DetectorConfig::NetMon(config) => crate::detector::netmon::check_rules(config),
            DetectorConfig::KernelMon(config) => crate::detector::kernelmon::check_rules(config),
            DetectorConfig::IOUringMon | DetectorConfig::SysEnumMon(_) => Ok(()),
        }
    }
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
            let mut yaml_config = std::fs::read_to_string(&config_path)?;
            // Empty file means the detector is loaded with default settings
            if yaml_config.trim().is_empty() {
                yaml_config = "{}".to_string();
            }
            let mut value: serde_yml::Value = serde_yml::from_str(yaml_config.as_ref())?;
            crate::rule::macros::expand_config(&mut value)?;
            let config = match name {
                "procmon" => {
                    let config: ProcMonConfig = serde_yml::from_value(value)?;
                    DetectorConfig::ProcMon(Arc::new(config))
                }
                "filemon" => {
                    let config: FileMonConfig = serde_yml::from_value(value)?;
                    DetectorConfig::FileMon(Arc::new(config))
                }
                "netmon" => {
                    let config: NetMonConfig = serde_yml::from_value(value)?;
                    DetectorConfig::NetMon(Arc::new(config))
                }
                "kernelmon" => {
                    let config: KernelMonConfig = serde_yml::from_value(value)?;
                    DetectorConfig::KernelMon(Arc::new(config))
                }
                "io_uringmon" => DetectorConfig::IOUringMon,
                "sysenummon" => {
                    let config: SysEnumMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
                    DetectorConfig::SysEnumMon(Arc::new(config))
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use tempfile::TempDir;

    fn repo_path(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path)
    }

    /// Parse detector configs from the directory and compile their rules
    fn check_config_dir(dir: &Path, detectors: Vec<String>) -> Result<(), anyhow::Error> {
        let options = Options {
            config_dir: dir.to_string_lossy().into_owned(),
            detectors: Some(detectors),
            ..Default::default()
        };
        let mut config = Config::new(options);
        config.parse_configs()?;
        for (name, detector_config) in &config.detector_configs {
            detector_config
                .check_rules()
                .map_err(|e| anyhow!("{name}: {e:#}"))?;
        }
        Ok(())
    }

    #[test]
    fn example_rules_compile() {
        // Each example is a single detector config named <detector>-<topic>.yaml
        for entry in std::fs::read_dir(repo_path("examples")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "yaml") {
                continue;
            }
            let file_name = path.file_name().unwrap().to_string_lossy();
            let detector = file_name.split('-').next().unwrap();
            let dir = TempDir::new().unwrap();
            std::fs::copy(&path, dir.path().join(format!("{detector}.yaml"))).unwrap();
            // procmon is always loaded, an empty config means defaults
            if detector != "procmon" {
                std::fs::write(dir.path().join("procmon.yaml"), "").unwrap();
            }
            check_config_dir(dir.path(), vec![detector.to_string()])
                .unwrap_or_else(|e| panic!("{file_name}: {e:#}"));
        }
    }

    #[test]
    fn config_dir_rules_compile() {
        for dir in ["install/config", "examples/quickstart"] {
            let dir = repo_path(dir);
            let config_yaml = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
            let options: Options = serde_yml::from_str(&config_yaml)
                .unwrap_or_else(|e| panic!("{}/config.yaml: {e}", dir.display()));
            // Check every detector config in the directory, not only the enabled ones
            let detectors: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.unwrap().path();
                    let stem = path.file_stem()?.to_string_lossy().into_owned();
                    (path.extension()? == "yaml" && stem != "config").then_some(stem)
                })
                .collect();
            for name in options.detectors.unwrap_or_default() {
                assert!(
                    detectors.contains(&name),
                    "{}: {name}.yaml is missing",
                    dir.display()
                );
            }
            check_config_dir(&dir, detectors)
                .unwrap_or_else(|e| panic!("{}: {e:#}", dir.display()));
        }
    }
}
