//! Config provides a global configuration for agent

use serde::Deserialize;

use clap::{Args, Parser};

use std::path::PathBuf;
use std::sync::LazyLock;
use tokio::sync::RwLock;

/// Ring buffer map name is used to send events
pub const EVENT_MAP_NAME: &str = "EVENT_MAP";

/// Procmon map name is used to hold alive processes
pub const PROCMON_PROC_MAP_NAME: &str = "PROCMON_PROC_MAP";

// Config holds options for cli interface and global agent parameters
#[derive(Default, Clone, Debug, Parser, Deserialize)]
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
    #[arg(long, value_name = "DIR", default_value_t = String::from("/usr/local/lib/bombini/config"))]
    #[serde(skip)]
    pub config_dir: String,

    #[command(flatten)]
    #[serde(skip)]
    pub transmit_opts: TransmitterOpts,
}

#[derive(Default, Clone, Debug, Args)]
#[group(multiple = false)]
pub struct TransmitterOpts {
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
        let args = Config::parse();
        self.config_dir = args.config_dir.to_string();

        let mut config_path = PathBuf::from(&self.config_dir);
        config_path.push("config.yaml"); // Global config name

        // YAML is overrided by command line args.
        let s = std::fs::read_to_string(&config_path)?;
        let config: Config = serde_yml::from_str(&s)?;
        self.bpf_objs = config.bpf_objs;
        self.maps_pin_path = config.maps_pin_path;
        self.event_channel_size = config.event_channel_size;
        self.event_map_size = config.event_map_size;
        self.procmon_proc_map_size = config.procmon_proc_map_size;
        self.detectors = config.detectors;

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

pub static CONFIG: LazyLock<RwLock<Config>> = LazyLock::new(|| RwLock::new(Config::default()));
