//! Options for agent configuration

use anyhow::bail;
use serde::Deserialize;

use clap::{Args, Parser};

use std::path::PathBuf;

/// Ring buffer map name is used to send events
pub const EVENT_MAP_NAME: &str = "EVENT_MAP";

/// Zero event map is used to clear event map ringbuffer entries
pub const ZERO_EVENT_MAP: &str = "ZERO_EVENT_MAP";

/// Procmon map name is used to hold alive processes
pub const PROCMON_PROC_MAP_NAME: &str = "PROCMON_PROC_MAP";

fn default_event_map_size() -> Option<u32> {
    Some(65536)
}

fn default_event_channel_size() -> Option<usize> {
    Some(64)
}

fn default_procmon_proc_map_size() -> Option<u32> {
    Some(8192)
}

fn default_gc_period() -> Option<u64> {
    Some(30)
}

// Options for cli interface and global agent parameters
#[derive(Default, Clone, Debug, Parser, Deserialize)]
#[command(name = "bombini", version)]
#[command(about = "Ebpf-based agent for observability and security monitoring", long_about = None)]
pub struct Options {
    /// Directory with bpf detector object files
    #[arg(long, value_name = "FILE")]
    pub bpf_objs: Option<String>,

    /// Path to pin bpf maps
    #[arg(long, value_name = "FILE")]
    pub maps_pin_path: Option<String>,

    /// Event map size (ring buffer size in bytes)
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_event_map_size")]
    pub event_map_size: Option<u32>,

    /// Raw event channel size (number of event messages)
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_event_channel_size")]
    pub event_channel_size: Option<usize>,

    /// Procmon process map size
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_procmon_proc_map_size")]
    pub procmon_proc_map_size: Option<u32>,

    /// Detector to load. Can be specified multiple times.
    /// Overrides the config.
    #[arg(short = 'D', long = "detector", value_name = "NAME")]
    pub detectors: Option<Vec<String>>,

    /// GC period for user mode caches in seconds.
    #[arg(long, value_name = "SEC")]
    #[serde(default = "default_gc_period")]
    pub gc_period: Option<u64>,

    /// YAML config dir with global config and detector configs
    #[arg(long, value_name = "DIR", default_value_t = String::from("/usr/local/lib/bombini/config"))]
    #[serde(skip)]
    pub config_dir: String,

    #[command(flatten)]
    #[serde(flatten)]
    pub transmit_opts: TransmitterOpts,

    #[command(flatten)]
    #[serde(flatten)]
    pub metric_opts: MetricOptions,
}

#[derive(Default, Clone, Debug, Args, Deserialize)]
#[group(multiple = false)]
#[serde(default)]
pub struct TransmitterOpts {
    /// File path to save events
    #[command(flatten)]
    #[serde(flatten)]
    pub event_file: FileLogOptions,

    /// Unix socket path to send events
    #[arg(long, value_name = "FILE", conflicts_with = "file_log")]
    pub event_socket: Option<String>,
}

fn default_log_file_rotations() -> Option<usize> {
    Some(5)
}
fn default_log_file_size() -> Option<usize> {
    Some(10)
}
fn default_log_file_compression() -> bool {
    false
}

#[derive(Default, Clone, Debug, Args, Deserialize)]
#[group(id = "file_log", required = false, multiple = true)]
#[serde(default)]
pub struct FileLogOptions {
    /// File path to save events
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Number of rotated files to keep
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_log_file_rotations")]
    pub log_file_rotations: Option<usize>,

    /// Max size of rotated file in mb
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_log_file_size")]
    pub log_file_size: Option<usize>,

    /// Enable compression for rotated files
    #[arg(long, value_name = "VALUE")]
    #[serde(default = "default_log_file_compression")]
    pub log_file_compression: bool,
}

#[derive(Default, Clone, Debug, Args, Deserialize)]
#[group(id = "metric", required = false, multiple = true)]
#[serde(default)]
pub struct MetricOptions {
    /// Prometheus exporter port
    #[arg(long, value_name = "PORT")]
    pub metric_server_port: Option<u16>,
}

impl Options {
    /// Method returns path for event map pin
    pub fn event_pin_path(&self) -> PathBuf {
        let mut event_pin = PathBuf::from(self.maps_pin_path.as_ref().unwrap());
        event_pin.push(EVENT_MAP_NAME);
        event_pin
    }

    /// Parse options from args and config.yaml
    pub fn parse_options(&mut self) -> Result<(), anyhow::Error> {
        let args = Options::parse();
        self.config_dir = args.config_dir.to_string();

        let mut config_path = PathBuf::from(&self.config_dir);
        config_path.push("config.yaml"); // Global config name

        // YAML is overrided by command line args.
        let s = std::fs::read_to_string(&config_path)?;
        let config: Options = serde_yml::from_str(&s)?;
        self.bpf_objs = config.bpf_objs;
        self.maps_pin_path = config.maps_pin_path;
        self.event_channel_size = config.event_channel_size;
        self.event_map_size = config.event_map_size;
        self.procmon_proc_map_size = config.procmon_proc_map_size;
        self.detectors = config.detectors;
        self.gc_period = config.gc_period;
        self.transmit_opts = config.transmit_opts;
        self.metric_opts = config.metric_opts;

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
        if let Some(v) = args.gc_period {
            self.gc_period = Some(v);
        }
        if let Some(detectors) = args.detectors {
            self.detectors = Some(detectors.to_vec());
        }
        if let Some(port) = args.metric_opts.metric_server_port {
            self.metric_opts.metric_server_port = Some(port);
        }

        // Serde doesn't support group validation, so we do it manually
        if self.transmit_opts.event_file.log_file.is_some()
            && self.transmit_opts.event_socket.is_some()
        {
            bail!("Only one of log-file or event-socket can be specified");
        }

        if let Some(log_file) = args.transmit_opts.event_file.log_file {
            self.transmit_opts.event_file.log_file = Some(log_file);
        }
        if let Some(log_file_rotations) = args.transmit_opts.event_file.log_file_rotations {
            self.transmit_opts.event_file.log_file_rotations = Some(log_file_rotations);
        }
        if let Some(log_file_size) = args.transmit_opts.event_file.log_file_size {
            self.transmit_opts.event_file.log_file_size = Some(log_file_size);
        }
        if args.transmit_opts.event_file.log_file_compression {
            self.transmit_opts.event_file.log_file_compression = true;
        }

        if args.transmit_opts.event_socket.is_some() {
            self.transmit_opts.event_socket = args.transmit_opts.event_socket;
        }

        Ok(())
    }
}
