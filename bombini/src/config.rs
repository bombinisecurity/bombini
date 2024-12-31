//! Config provides a global configuration for agent

use yaml_rust2::YamlLoader;

use clap::Parser;
use lazy_static::lazy_static;
use tokio::sync::RwLock;

use std::path::PathBuf;

/// Ring buffer map name used to send events
pub const EVENT_MAP_NAME: &str = "EVENT_MAP";

// Config holds options for cli interface and global agent parameters
#[derive(Default, Clone, Debug, Parser)]
#[command(name = "bombini", version)]
#[command(about = "Ebpf-based agent for observability and security monitoring", long_about = None)]
pub struct Config {
    /// Directory with bpf detector object files
    #[arg(long, value_name = "FILE", default_value_t = String::from("/home/fedotoff/bombini/target/bpfel-unknown-none/debug"))]
    pub bpf_objs: String,

    /// Path to pin bpf maps
    #[arg(long, value_name = "FILE", default_value_t = String::from("/sys/fs/bpf/bombini"))]
    pub maps_pin_path: String,

    /// Event map size (ring buffer size in bytes)
    #[arg(long, value_name = "VALUE", default_value_t = 65536)]
    pub event_map_size: u32,

    /// Raw event channel size (number of event messages)
    #[arg(long, value_name = "VALUE", default_value_t = 64)]
    pub event_channel_size: usize,

    /// List of detectors to load
    #[arg(long, value_name = "NAMES")]
    pub detectors: Option<Vec<String>>,

    /// YAML config dir with global config and detector configs
    #[arg(long, value_name = "DIR", default_value_t = String::from("/home/fedotoff/bombini/config"))]
    pub config_dir: String,
}

impl Config {
    /// Method returns path for event map pin
    pub fn event_pin_path(&self) -> PathBuf {
        let mut event_pin = PathBuf::from(&self.maps_pin_path);
        event_pin.push(EVENT_MAP_NAME);
        event_pin
    }

    /// Creates new config from args and yaml
    pub fn init(&mut self) -> Result<(), anyhow::Error> {
        //TODO: maybe change to serde_yaml

        *self = Config::parse();

        let mut config_path = PathBuf::from(&self.config_dir);
        config_path.push("config.yaml"); // Global config name

        // YAML overrides command line args.
        if let Ok(s) = std::fs::read_to_string(&config_path) {
            let docs = YamlLoader::load_from_str(&s)?;

            //TODO: accurate checks if value is in yaml than use it, else use from args.
            let doc = &docs[0];

            if let Some(v) = doc["bpf_objs"].as_str() {
                self.bpf_objs = v.to_string();
            }

            if let Some(v) = doc["maps_pin_path"].as_str() {
                self.maps_pin_path = v.to_string();
            }

            if let Some(v) = doc["event_map_size"].as_i64() {
                self.event_map_size = v as u32;
            }

            if let Some(v) = doc["event_channel_size"].as_i64() {
                self.event_channel_size = v as usize;
            }

            if let Some(detectors) = doc["detectors"].as_vec() {
                self.detectors = Some(
                    detectors
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect(),
                );
            }
        }
        Ok(())
    }
}

lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(Config::default());
}
