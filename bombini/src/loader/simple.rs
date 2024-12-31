//! Loader for simple detector

use aya::maps::Array;
use aya::programs::KProbe;
use aya::{Ebpf, EbpfError};

use procfs::sys::kernel::Version;
use yaml_rust2::YamlLoader;

use bombini_common::config::simple::SimpleUIDFilter;

use std::path::Path;

use super::{load_ebpf_obj, Loader};

pub struct SimpleLoader {
    ebpf: Ebpf,
    config: Option<SimpleConfig>,
}

struct SimpleConfig {
    /// Entry values for SIMPLE_CONFIG map
    simple_uid_filter_entries: Vec<(u32, SimpleUIDFilter)>,
}

impl Loader for SimpleLoader {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 7, 0)
    }

    async fn new<U: AsRef<Path>>(obj_path: U, config_path: Option<U>) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        if let Some(config_path) = config_path {
            // Get config
            let mut config = SimpleConfig {
                simple_uid_filter_entries: Vec::new(),
            };

            let s = std::fs::read_to_string(config_path.as_ref())?;
            let docs = YamlLoader::load_from_str(&s)?;
            let doc = &docs[0];

            // TODO: safe parsing
            if let Some(entries) = doc["maps"]["simple_uid_filter"].as_vec() {
                for entry in entries {
                    let v = entry["value"].as_i64().unwrap() as u32;
                    config.simple_uid_filter_entries.push((
                        entry["key"].as_i64().unwrap() as u32,
                        SimpleUIDFilter { uid: v },
                    ));
                }
            }
            Ok(SimpleLoader { ebpf, config: Some(config)})
        } else {
            Ok(SimpleLoader { ebpf, config: None})
        }
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(config) = &self.config {
            if let Some((k, v)) = config.simple_uid_filter_entries.first() {
                let mut filter: Array<_, SimpleUIDFilter> =
                    Array::try_from(self.ebpf.map_mut("SIMPLE_UID_FILTER").unwrap())?;
                filter.set(*k, v, 0)?;
            }
        }
        Ok(())
    }

    fn load_and_attach(&mut self) -> Result<(), EbpfError> {
        let program: &mut KProbe = self.ebpf.program_mut("simple").unwrap().try_into()?;
        program.load()?;
        program.attach("security_bprm_check", 0)?;
        Ok(())
    }
}
