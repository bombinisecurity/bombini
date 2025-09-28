use log::info;
use scopeguard::defer;
use tokio::signal;

mod config;
mod detector;
mod monitor;
mod proto;
mod registry;
mod transmitter;
mod transmuter;

use config::{Config, CONFIG};
use monitor::Monitor;
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

    {
        let mut config = CONFIG.write().await;
        config.init()?;
    }

    let config = CONFIG.read().await;

    if std::fs::exists(config.maps_pin_path.as_ref().unwrap()).unwrap() {
        anyhow::bail!(
            "Map pin directory {} exists. Remove it to start.",
            config.maps_pin_path.as_ref().unwrap()
        );
    }

    let _ = std::fs::create_dir(config.maps_pin_path.as_ref().unwrap());
    defer! {
        let _ = std::fs::remove_dir_all(config.maps_pin_path.as_ref().unwrap());
    }

    let mut registry = Registry::new();
    registry.load_detectors().await?;

    let event_pin_path = config.event_pin_path();
    let monitor = Monitor::new(event_pin_path.as_path(), config.event_channel_size.unwrap());
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

async fn start_monitor(config: &Config, monitor: &Monitor<'_>) -> Result<(), anyhow::Error> {
    if let Some(file) = &config.transmit_opts.event_log {
        monitor.monitor(FileTransmitter::new(file).await?).await;
        Ok(())
    } else if let Some(file) = &config.transmit_opts.event_socket {
        monitor.monitor(USockTransmitter::new(file).await?).await;
        Ok(())
    } else {
        // default: send events to stdout
        monitor.monitor(StdoutTransmitter).await;
        Ok(())
    }
}
