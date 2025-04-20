use log::info;
use scopeguard::defer;
use tokio::signal;

mod config;
mod detector;
mod monitor;
mod registry;
mod transmitter;
mod transmuter;

use config::{Config, CONFIG};
use monitor::Monitor;
use registry::Registry;
use transmitter::file::FileTransmitter;
use transmitter::log::LogTransmitter;
use transmitter::unix_sock::USockTransmitter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    {
        let mut config = CONFIG.write().await;
        config.init()?;
    }

    let config = CONFIG.read().await;

    let _ = std::fs::create_dir(config.maps_pin_path.as_ref().unwrap());
    defer! {
        let _ = std::fs::remove_dir_all(config.maps_pin_path.as_ref().unwrap());
    }

    let mut registry = Registry::new();
    registry.load_detectors().await?;

    let event_pin_path = config.event_pin_path();
    let monitor = Monitor::new(event_pin_path.as_path(), config.event_channel_size.unwrap());
    start_monitor(&config, &monitor).await?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

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
        monitor.monitor(LogTransmitter).await;
        Ok(())
    }
}
