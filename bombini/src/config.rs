//! Config provides a global configuration for agent

use yaml_rust2::YamlLoader;

use clap::{Args, Parser};
use lazy_static::lazy_static;
use tokio::sync::RwLock;

use std::path::PathBuf;

/// Ring buffer map name is used to send events
pub const EVENT_MAP_NAME: &str = "EVENT_MAP";

/// Procmon map name is used to hold alive processes
pub const PROCMON_PROC_MAP_NAME: &str = "PROCMON_PROC_MAP";

// Config holds options for cli interface and global agent parameters
#[derive(Default, Clone, Debug, Parser)]
#[command(name = "bombini", version)]
#[command(about = "Ebpf-based agent for observability and security monitoring", long_about = None)]
pub struct Config {
    /// Directory with bpf detector object files
    #[arg(long, value_name = "FILE")]
    pub bpf_objs: Option<String>,

    /// Path to pin bpf maps
    #[arg(long, value_name = "FILE")]
    pub maps_pin_path: Option<String>,

    /// Event map size (ring buffer size in bytes)
    /// default value: 65536
    #[arg(long, value_name = "VALUE")]
    pub event_map_size: Option<u32>,

    /// Raw event channel size (number of event messages)
    /// default value: 64
    #[arg(long, value_name = "VALUE")]
    pub event_channel_size: Option<usize>,

    /// Procmon process map size
    /// default value: 8192
    #[arg(long, value_name = "VALUE")]
    pub procmon_proc_map_size: Option<u32>,

    /// Detector to load. Can be specified multiple times.
    /// Overrides the config.
    #[arg(short = 'D', long = "detector", value_name = "NAME")]
    pub detectors: Option<Vec<String>>,

    /// YAML config dir with global config and detector configs
    #[arg(long, value_name = "DIR")]
    pub config_dir: String,

    #[command(flatten)]
    pub transmit_opts: TransmitterOpts,
}

#[derive(Default, Clone, Debug, Args)]
#[group(required = true, multiple = false)]
pub struct TransmitterOpts {
    /// Send events to stdout
    #[arg(long)]
    pub stdout: bool,

    /// File path to save events
    #[arg(long, value_name = "FILE")]
    pub event_log: Option<String>,

    /// Unix socket path to send events
    #[arg(long, value_name = "FILE")]
    pub event_socket: Option<String>,
}

impl Config {
    /// Method returns path for event map pin
    pub fn event_pin_path(&self) -> PathBuf {
        let mut event_pin = PathBuf::from(self.maps_pin_path.as_ref().unwrap());
        event_pin.push(EVENT_MAP_NAME);
        event_pin
    }

    /// Creates new config from args and yaml
    pub fn init(&mut self) -> Result<(), anyhow::Error> {
        //TODO: maybe change to serde_yaml
        let args = Config::parse();
        self.config_dir = args.config_dir.to_string();

        let mut config_path = PathBuf::from(&self.config_dir);
        config_path.push("config.yaml"); // Global config name

        // YAML overrides command line args.
        let s = std::fs::read_to_string(&config_path)?;
        let docs = YamlLoader::load_from_str(&s)?;

        // TODO: check that config has required field
        let doc = &docs[0];

        if let Some(v) = doc["bpf_objs"].as_str() {
            let mut abs_bpf_objs = PathBuf::from(&self.config_dir).canonicalize()?;
            let bpf_objs = PathBuf::from(v.to_string());
            if bpf_objs.is_absolute() {
                self.bpf_objs = Some(bpf_objs.to_str().unwrap().to_string());
            } else {
                abs_bpf_objs.push(bpf_objs);
                self.bpf_objs = Some(abs_bpf_objs.to_str().unwrap().to_string());
            }
        }

        if let Some(v) = doc["maps_pin_path"].as_str() {
            let mut abs_pin_path = PathBuf::from(&self.config_dir).canonicalize()?;
            let pin_path = PathBuf::from(v.to_string());
            if pin_path.is_absolute() {
                self.maps_pin_path = Some(pin_path.to_str().unwrap().to_string());
            } else {
                abs_pin_path.push(pin_path);
                self.maps_pin_path = Some(abs_pin_path.to_str().unwrap().to_string());
            }
        }

        if let Some(v) = doc["event_map_size"].as_i64() {
            self.event_map_size = Some(v as u32);
        } else {
            self.event_map_size = Some(65536);
        }

        if let Some(v) = doc["event_channel_size"].as_i64() {
            self.event_channel_size = Some(v as usize);
        } else {
            self.event_channel_size = Some(64);
        }

        if let Some(v) = doc["procmon_proc_map_size"].as_i64() {
            self.procmon_proc_map_size = Some(v as u32);
        } else {
            self.procmon_proc_map_size = Some(8192);
        }

        if let Some(detectors) = doc["detectors"].as_vec() {
            self.detectors = Some(
                detectors
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect(),
            );
        }

        // Redefine config from file if command args are set
        if let Some(v) = args.bpf_objs.as_deref() {
            let path = PathBuf::from(v.to_string()).canonicalize()?;
            self.bpf_objs = Some(path.to_str().unwrap().to_string());
        }
        if let Some(v) = args.maps_pin_path.as_deref() {
            self.maps_pin_path = Some(v.to_string());
        }
        if let Some(v) = args.event_map_size {
            self.event_map_size = Some(v);
        }
        if let Some(v) = args.event_channel_size {
            self.event_channel_size = Some(v);
        }
        if let Some(v) = args.procmon_proc_map_size {
            self.procmon_proc_map_size = Some(v);
        }
        if let Some(detectors) = args.detectors {
            self.detectors = Some(detectors.to_vec());
        }

        // Use transmitter options only from args
        self.transmit_opts = args.transmit_opts;

        Ok(())
    }
}

lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(Config::default());
}
