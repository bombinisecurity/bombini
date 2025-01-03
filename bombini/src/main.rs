use log::info;
use tokio::signal;

mod config;
mod detector;
mod monitor;
mod registry;

use config::CONFIG;
use monitor::Monitor;
use registry::Registry;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    {
        let mut config = CONFIG.write().await;
        config.init()?;
    }

    let config = CONFIG.read().await;

    let _ = std::fs::create_dir(&config.maps_pin_path);

    let mut registry = Registry::new();
    registry.load_detecors().await?;

    let event_pin_path = config.event_pin_path();
    let monitor = Monitor::new(event_pin_path.as_path(), config.event_channel_size);
    monitor.monitor().await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    let _ = std::fs::remove_file(&event_pin_path);
    info!("Exiting...");

    Ok(())
}
