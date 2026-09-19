use log::info;
use nix::fcntl::{Flock, FlockArg};
use scopeguard::defer;
use tokio::signal;

use std::fs::File;
use std::path::PathBuf;

mod config;
mod detector;
mod k8s;
mod metrics;
mod monitor;
mod options;
mod proto;
mod registry;
mod rule;
mod transmitter;
mod transmuter;

use rule::ast;

use config::Config;
use monitor::Monitor;
use options::Options;
use registry::Registry;
use transmitter::file::FileTransmitter;
use transmitter::stdout::StdoutTransmitter;
use transmitter::unix_sock::USockTransmitter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Failed to set up SIGINT handler");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Failed to set up SIGTERM handler");

    env_logger::init();

    let mut options = Options::default();
    options.parse_options()?;
    let mut config = Config::new(options);
    config.parse_configs()?;

    // bpffs does not support ordinary files (only mkdir and BPF_OBJ_PIN), but
    // flock on the pin directory itself works fine and needs no extra file.
    let maps_pin_path = PathBuf::from(config.options.maps_pin_path.as_ref().unwrap());
    if std::fs::exists(&maps_pin_path)? {
        match Flock::lock(File::open(&maps_pin_path)?, FlockArg::LockExclusiveNonblock) {
            Ok(_lock) => {
                info!(
                    "Map pin directory {} is stale (owner is gone), cleaning up",
                    maps_pin_path.display()
                );
                std::fs::remove_dir_all(&maps_pin_path)?;
            }
            Err((_, e)) => {
                anyhow::bail!(
                    "Map pin directory {} exists and is in use ({e}). Another instance may be running.",
                    maps_pin_path.display()
                );
            }
        }
    }
    std::fs::create_dir(&maps_pin_path)?;
    defer! {
        let _ = std::fs::remove_dir_all(&maps_pin_path);
    }
    let _pin_dir_lock =
        Flock::lock(File::open(&maps_pin_path)?, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| anyhow::anyhow!("Failed to lock {}: {e}", maps_pin_path.display()))?;

    let mut registry = Registry::new();
    registry.load_detectors(&config)?;
    let k8s = k8s::start(&config.options.k8s_opts).await?;
    let monitor = Monitor::new(k8s.as_ref().map(|k8s| k8s.index.clone()));

    if let Some(port) = config.options.metric_opts.metric_server_port {
        let mut metric_server = metrics::BombiniMetricServer::new();
        metric_server.register_metrics(&monitor);
        if let Some(k8s) = &k8s {
            metric_server.register_metrics(k8s);
        }

        metric_server.start_local_server(port).await?;
    }

    start_monitor(&config, &monitor).await?;

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT (Ctrl+C), exiting...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, exiting...");
        }
    }

    Ok(())
}

async fn start_monitor(config: &Config, monitor: &Monitor) -> Result<(), anyhow::Error> {
    if config.options.transmit_opts.event_file.log_file.is_some() {
        monitor
            .monitor(
                config,
                FileTransmitter::new(
                    config.options.transmit_opts.event_file.clone(),
                    config.options.event_channel_size.unwrap(),
                    monitor.events_lost_counter(),
                )
                .await?,
            )
            .await;
        Ok(())
    } else if let Some(file) = &config.options.transmit_opts.event_socket {
        monitor
            .monitor(config, USockTransmitter::new(file).await?)
            .await;
        Ok(())
    } else {
        // default: send events to stdout
        monitor.monitor(config, StdoutTransmitter::new()).await;
        Ok(())
    }
}
