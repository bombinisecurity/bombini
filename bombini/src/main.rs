use log::info;
use tokio::signal;

use std::path::Path;

mod detector;
mod loader;
mod monitor;

use detector::Detector;
use loader::gtfobins::GtfobinsLoader;
use loader::simple::SimpleLoader;
use monitor::Monitor;

const EVENT_PIN_PATH: &str = "/sys/fs/bpf/bombini/EVENT_MAP";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let _ = std::fs::create_dir("/sys/fs/bpf/bombini");

    let mut simple_detector = Detector::create(
        "/home/fedotoff/bombini/target/bpfel-unknown-none/debug/simple",
        SimpleLoader,
    )?;
    simple_detector.load()?;

    let mut gtfobins_detector = Detector::create(
        "/home/fedotoff/bombini/target/bpfel-unknown-none/debug/gtfobins",
        GtfobinsLoader,
    )?;
    gtfobins_detector.load()?;

    let monitor = Monitor::new(Path::new(EVENT_PIN_PATH), 64);
    monitor.monitor().await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    let _ = std::fs::remove_file(EVENT_PIN_PATH);
    info!("Exiting...");

    Ok(())
}
