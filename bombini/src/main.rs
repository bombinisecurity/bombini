use log::info;
use scopeguard::defer;
use tokio::signal;

mod config;
mod detector;
mod k8s_info;
mod monitor;
mod options;
mod proto;
mod registry;
mod transmitter;
mod transmuter;

use config::Config;
use k8s_info::K8sInfo;
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

    if std::fs::exists(config.options.maps_pin_path.as_ref().unwrap()).unwrap() {
        anyhow::bail!(
            "Map pin directory {} exists. Remove it to start.",
            config.options.maps_pin_path.as_ref().unwrap()
        );
    }

    let k8s_info = K8sInfo::new().await;
    let _ = std::fs::create_dir(config.options.maps_pin_path.as_ref().unwrap());
    defer! {
        let _ = std::fs::remove_dir_all(config.options.maps_pin_path.as_ref().unwrap());
    }

    let mut registry = Registry::new();
    registry.load_detectors(&config)?;
    let monitor = Monitor;
    start_monitor(&config, &monitor, k8s_info).await?;

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

async fn start_monitor(
    config: &Config,
    monitor: &Monitor,
    k8s_info: K8sInfo,
) -> Result<(), anyhow::Error> {
    if let Some(file) = &config.options.transmit_opts.event_log {
        monitor
            .monitor(config, FileTransmitter::new(file).await?, k8s_info)
            .await;
        Ok(())
    } else if let Some(file) = &config.options.transmit_opts.event_socket {
        monitor
            .monitor(config, USockTransmitter::new(file).await?, k8s_info)
            .await;
        Ok(())
    } else {
        monitor.monitor(config, StdoutTransmitter, k8s_info).await;
        Ok(())
    }
}
