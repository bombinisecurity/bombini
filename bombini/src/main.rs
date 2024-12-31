use log::info;
use tokio::signal;

mod config;
mod detector;
mod loader;
mod monitor;

use std::path::PathBuf;

use config::CONFIG;
use detector::Detector;
use loader::gtfobins::GTFOBinsLoader;
use loader::simple::SimpleLoader;
use loader::Loader;
use monitor::Monitor;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    {
        let mut config = CONFIG.write().await;
        config.init()?;
    }

    let config = CONFIG.read().await;

    let _ = std::fs::create_dir(&config.maps_pin_path);

    let mut detector_obj_path = PathBuf::from(&config.bpf_objs);
    detector_obj_path.push("simple");
    let mut detector_config_path = PathBuf::from(&config.config_dir);
    detector_config_path.push("simple.yaml");
    let simple_loader =
        SimpleLoader::new(&detector_obj_path, Some(&detector_config_path)).await?;
    let mut simple_detector = Detector::create("simple", simple_loader)?;
    simple_detector.load()?;

    detector_obj_path.pop();
    detector_obj_path.push("gtfobins");
    detector_config_path.pop();
    detector_config_path.push("gtfobins.yaml");
    let gtfobins_loader =
        GTFOBinsLoader::new(&detector_obj_path, Some(&detector_config_path))
            .await?;
    let mut gtfobins_detector = Detector::create("gtfobins", gtfobins_loader)?;
    gtfobins_detector.load()?;

    let event_pin_path = config.event_pin_path();
    let monitor = Monitor::new(event_pin_path.as_path(), config.event_channel_size);
    monitor.monitor().await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    let _ = std::fs::remove_file(&event_pin_path);
    info!("Exiting...");

    Ok(())
}
