//! File monitor detector

use aya::maps::Array;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfError};

use procfs::sys::kernel::Version;
use yaml_rust2::{Yaml, YamlLoader};

use std::path::Path;

use bombini_common::config::filemon::{Config, HookConfig};

use super::{load_ebpf_obj, Detector};

pub struct FileMon {
    ebpf: Ebpf,
    config: Option<Config>,
}

impl Detector for FileMon {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 11, 0)
    }

    async fn new<U: AsRef<Path>>(
        obj_path: U,
        config_path: Option<U>,
    ) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        if let Some(config_path) = config_path {
            let mut config = Config {
                file_open_config: HookConfig {
                    expose_events: true,
                    disable: false,
                },
                path_truncate_config: HookConfig {
                    expose_events: true,
                    disable: false,
                },
                path_unlink_config: HookConfig {
                    expose_events: true,
                    disable: false,
                },
            };

            let s = std::fs::read_to_string(config_path.as_ref())?;
            let docs = YamlLoader::load_from_str(&s)?;
            let Some(doc) = docs[0].as_hash() else {
                anyhow::bail!("filemon config must be a Hash")
            };

            if let Some(hook) = doc.get(&Yaml::from_str("file-open")) {
                config.file_open_config.expose_events =
                    hook["expose-events"].as_bool().unwrap_or(true);
                config.file_open_config.disable = hook["disable"].as_bool().unwrap_or(false);
            }

            if let Some(hook) = doc.get(&Yaml::from_str("path-truncate")) {
                config.path_truncate_config.expose_events =
                    hook["expose-events"].as_bool().unwrap_or(true);
                config.path_truncate_config.disable = hook["disable"].as_bool().unwrap_or(false);
            }

            if let Some(hook) = doc.get(&Yaml::from_str("path-truncate")) {
                config.path_unlink_config.expose_events =
                    hook["expose-events"].as_bool().unwrap_or(true);
                config.path_unlink_config.disable = hook["disable"].as_bool().unwrap_or(false);
            }

            Ok(FileMon {
                ebpf,
                config: Some(config),
            })
        } else {
            Ok(FileMon { ebpf, config: None })
        }
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(config) = self.config {
            let mut config_map: Array<_, Config> =
                Array::try_from(self.ebpf.map_mut("FILEMON_CONFIG").unwrap())?;
            let _ = config_map.set(0, config, 0);
        }
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;

        if self.config.is_none() || !self.config.unwrap().file_open_config.disable {
            let open: &mut Lsm = self
                .ebpf
                .program_mut("file_open_capture")
                .unwrap()
                .try_into()?;
            open.load("file_open", &btf)?;
            open.attach()?;
        }
        if self.config.is_none() || !self.config.unwrap().path_truncate_config.disable {
            let truncate: &mut Lsm = self
                .ebpf
                .program_mut("path_truncate_capture")
                .unwrap()
                .try_into()?;
            truncate.load("path_truncate", &btf)?;
            truncate.attach()?;
        }
        if self.config.is_none() || !self.config.unwrap().path_unlink_config.disable {
            let unlink: &mut Lsm = self
                .ebpf
                .program_mut("path_unlink_capture")
                .unwrap()
                .try_into()?;
            unlink.load("path_unlink", &btf)?;
            unlink.attach()?;
        }
        Ok(())
    }
}
