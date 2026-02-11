//! Registry contains loaded detectors

use log::debug;

use anyhow::anyhow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::{Config, DetectorConfig};
use crate::detector::filemon::FileMon;
use crate::detector::gtfobins::GTFOBinsDetector;
use crate::detector::io_uringmon::IOUringMon;

use crate::detector::Detector;
use crate::detector::netmon::NetMon;
use crate::detector::netmon_new::NetMonNew;
use crate::detector::procmon::ProcMon;

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

    pub fn load_detectors(&mut self, config: &Config) -> Result<(), anyhow::Error> {
        let mut obj_path = PathBuf::from(config.options.bpf_objs.as_ref().unwrap());
        let mut config_path = PathBuf::from(&config.options.config_dir);
        let maps_pin_path = PathBuf::from(config.options.maps_pin_path.as_ref().unwrap());

        // Load ProcMon first.
        // ProcMon provides process information that is used by all other detectors.
        let name = "procmon".to_string();
        let DetectorConfig::ProcMon(procmon_cfg) = config.detector_configs.get(&name).unwrap()
        else {
            return Err(anyhow!("ProcMon config is not found"));
        };
        obj_path.push(&name);
        let mut procmon = ProcMon::new(
            &obj_path,
            &maps_pin_path,
            config.options.event_map_size.unwrap(),
            config.options.procmon_proc_map_size.unwrap(),
            procmon_cfg.clone(),
        )?;
        procmon.load()?;
        self.detectors.insert(name, Box::new(procmon));
        debug!("Detector procmon is loaded");

        let names = config.options.detectors.as_ref().unwrap();
        for name in names.iter().map(|e| e.as_str()).filter(|e| *e != "procmon") {
            obj_path.pop();
            obj_path.push(name);

            let Some(config) = config.detector_configs.get(name) else {
                return Err(anyhow!("{} unknown detector", name));
            };
            self.load_detector(name, &obj_path, &maps_pin_path, config)?;
            config_path.pop();
        }
        Ok(())
    }

    fn load_detector(
        &mut self,
        name: &str,
        obj_path: &Path,
        maps_pin_path: &Path,
        config: &DetectorConfig,
    ) -> Result<(), anyhow::Error> {
        match config {
            DetectorConfig::FileMon(cfg) => {
                let mut detector = FileMon::new(obj_path, maps_pin_path, cfg.clone())?;
                detector.load()?;
                self.detectors.insert(name.to_string(), Box::new(detector));
            }
            DetectorConfig::NetMon(cfg) => {
                let mut detector = NetMon::new(obj_path, maps_pin_path, cfg.clone())?;
                detector.load()?;
                self.detectors.insert(name.to_string(), Box::new(detector));
            }
            DetectorConfig::NetMonNew(cfg) => {
                let mut detector = NetMonNew::new(obj_path, maps_pin_path, cfg.clone())?;
                detector.load()?;
                self.detectors.insert(name.to_string(), Box::new(detector));
            }
            DetectorConfig::IOUringMon(cfg) => {
                let mut detector = IOUringMon::new(obj_path, maps_pin_path, cfg.clone())?;
                detector.load()?;
                self.detectors.insert(name.to_string(), Box::new(detector));
            }
            DetectorConfig::GTFOBins(cfg) => {
                let mut detector = GTFOBinsDetector::new(obj_path, maps_pin_path, cfg.clone())?;
                detector.load()?;
                self.detectors.insert(name.to_string(), Box::new(detector));
            }
            _ => {
                return Err(anyhow!("{} unknown detector", name));
            }
        }
        debug!("Detector {name} is loaded");
        Ok(())
    }
}
