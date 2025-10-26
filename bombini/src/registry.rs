//! Registry contains loaded detectors

use log::debug;

use anyhow::anyhow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::CONFIG;
use crate::detector::gtfobins::GTFOBinsDetector;
use crate::detector::histfile::HistFileDetector;
use crate::detector::io_uringmon::IOUringMon;

use crate::detector::Detector;
use crate::detector::filemon::FileMon;
use crate::detector::netmon::NetMon;
use crate::detector::procmon::ProcMon;

macro_rules! load_detector {
    ($detectors:expr, $name:expr, $obj:expr, $config:expr, $(($key:expr, $type:ty)),+) => {
        match $name {
            $($key => {
                let mut detector = <$type>::new($obj, $config).await?;
                detector.load()?;
                $detectors.insert($name.to_string(), Box::new(detector));
                Ok(())
            },)+
            _ => Err(anyhow!("{} unknown detector", $name))
        }
    };
}

pub struct Registry {
    /// Loader Detectors
    detectors: HashMap<String, Box<dyn Detector>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            detectors: HashMap::new(),
        }
    }

    pub async fn load_detectors(&mut self) -> Result<(), anyhow::Error> {
        let config = CONFIG.read().await;
        let Some(ref names) = config.detectors else {
            return Ok(());
        };
        let config = CONFIG.read().await;
        let mut obj_path = PathBuf::from(config.bpf_objs.as_ref().unwrap());
        let mut config_path = PathBuf::from(&config.config_dir);
        for name in names.iter().map(|e| e.as_str()) {
            obj_path.push(name);
            config_path.push(name.to_owned() + ".yaml");
            let yaml_config = std::fs::read_to_string(&config_path).ok();
            self.load_detector(name, &obj_path, yaml_config).await?;
            obj_path.pop();
            config_path.pop();
        }
        Ok(())
    }

    pub async fn load_detector(
        &mut self,
        name: &str,
        obj_path: &Path,
        yaml_config: Option<String>,
    ) -> Result<(), anyhow::Error> {
        load_detector!(
            &mut self.detectors,
            name,
            obj_path,
            yaml_config,
            /* List of supported Detecotors */
            ("procmon", ProcMon),
            ("filemon", FileMon),
            ("netmon", NetMon),
            ("io_uringmon", IOUringMon),
            ("gtfobins", GTFOBinsDetector),
            ("histfile", HistFileDetector)
        )?;

        debug!("Detector {name} is loaded");
        Ok(())
    }
}
