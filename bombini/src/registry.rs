//! Registry contains loaded detectors

use log::debug;

use anyhow::anyhow;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::CONFIG;
use crate::detector::gtfobins::GTFOBinsDetector;
use crate::detector::procmon::ProcMon;
use crate::detector::Detector;

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

    pub async fn load_detecors(&mut self) -> Result<(), anyhow::Error> {
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
            match name {
                "gtfobins" => {
                    let mut detector = GTFOBinsDetector::new(&obj_path, Some(&config_path)).await?;
                    detector.load()?;
                    self.detectors.insert(name.to_string(), Box::new(detector));
                }
                "procmon" => {
                    let mut procmon = ProcMon::new(&obj_path, None).await?;
                    procmon.load()?;
                    self.detectors.insert(name.to_string(), Box::new(procmon));
                }
                _ => return Err(anyhow!("{} unknown detector", name)),
            };

            debug!("Detector {} is loaded", name);
            obj_path.pop();
            config_path.pop();
        }
        Ok(())
    }
}
