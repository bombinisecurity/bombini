//! Transmuter provides an interface to transmute raw eBPF events into
//! serialized formats

use chrono::{DateTime, SecondsFormat};
use nix::time::{ClockId, clock_gettime};

use anyhow::anyhow;
use std::{sync::Arc, time::Duration};

use bombini_common::event::{
    Event, GenericEvent, MSG_FILE, MSG_GTFOBINS, MSG_IOURING, MSG_NETWORK, MSG_PROCESS,
    MSG_PROCESS_CLONE, MSG_PROCESS_EXEC, MSG_PROCESS_EXIT,
    process::{ProcInfo, ProcessKey},
};

mod cache;
mod file;
mod gtfobins;
mod io_uring;
mod network;
mod process;

use crate::{
    config::{Config, DetectorConfig},
    transmuter::cache::process::{CachedProcess, ProcessCache},
};

use file::FileEventTransmuter;
use gtfobins::GTFOBinsEventTransmuter;
use io_uring::IOUringEventTransmuter;
use network::NetworkEventTransmuter;
use process::{
    Process, ProcessCloneTransmuter, ProcessEventTransmuter, ProcessExecTransmuter,
    ProcessExitTransmuter,
};

pub struct TransmuterRegistry {
    handlers: [Option<Arc<dyn Transmuter>>; 256],
    process_cache: ProcessCache,
}
impl TransmuterRegistry {
    pub fn new(config: &Config) -> Self {
        let mut registry = Self {
            handlers: std::array::from_fn(|_| None),
            process_cache: ProcessCache::with_capacity(
                config.options.procmon_proc_map_size.unwrap() as usize,
            ),
        };

        // Init Process cache
        let current_processes = procfs::process::all_processes().unwrap();
        current_processes
            .filter_map(|p| p.ok())
            .filter(|p| p.is_alive())
            .filter_map(|p| ProcInfo::from_procfs(&p))
            .for_each(|p| {
                let key = ProcessKey {
                    pid: p.pid,
                    start: p.start,
                };
                let process = CachedProcess {
                    process: Arc::new(Process::new(&p)),
                    exited: false,
                };
                let _ = registry.process_cache.insert(key, process);
            });

        // Install transmuters according loaded detectors
        for detector_cfg in config.detector_configs.values() {
            match detector_cfg {
                DetectorConfig::ProcMon(_) => {
                    registry.handlers[MSG_PROCESS_EXEC as usize] =
                        Some(Arc::new(ProcessExecTransmuter));
                    registry.handlers[MSG_PROCESS_CLONE as usize] =
                        Some(Arc::new(ProcessCloneTransmuter));
                    registry.handlers[MSG_PROCESS_EXIT as usize] =
                        Some(Arc::new(ProcessExitTransmuter));
                    registry.handlers[MSG_PROCESS as usize] =
                        Some(Arc::new(ProcessEventTransmuter));
                }
                DetectorConfig::FileMon(_) => {
                    registry.handlers[MSG_FILE as usize] = Some(Arc::new(FileEventTransmuter));
                }
                DetectorConfig::NetMon(_) | DetectorConfig::NetMonNew(_) => {
                    registry.handlers[MSG_NETWORK as usize] =
                        Some(Arc::new(NetworkEventTransmuter));
                }
                DetectorConfig::IOUringMon => {
                    registry.handlers[MSG_IOURING as usize] =
                        Some(Arc::new(IOUringEventTransmuter));
                }
                DetectorConfig::GTFOBins(_) => {
                    registry.handlers[MSG_GTFOBINS as usize] =
                        Some(Arc::new(GTFOBinsEventTransmuter));
                }
            }
        }
        registry
    }

    pub fn transmute(&mut self, generic_event: &GenericEvent) -> Result<Vec<u8>, anyhow::Error> {
        let event_type = generic_event.msg_code as usize;
        if let Some(handler) = self.handlers[event_type].as_ref() {
            handler.transmute(
                &generic_event.event,
                generic_event.ktime,
                &mut self.process_cache,
            )
        } else {
            Err(anyhow!(
                "No transmuter for event type {}",
                generic_event.msg_code
            ))
        }
    }

    pub fn retain_caches(&mut self) {
        self.process_cache.retain(|_, p| !p.exited);
    }
}

pub trait Transmuter: Send + Sync {
    /// Transmutes low-level event to high level and serialized representation
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error>;
}

pub fn str_from_bytes(bytes: &[u8]) -> String {
    if let Some(zero) = bytes.iter().position(|e| *e == 0x0) {
        String::from_utf8_lossy(&bytes[..zero]).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

pub fn transmute_ktime(ktime: u64) -> String {
    let Ok(cur_time_boot) = clock_gettime(ClockId::CLOCK_BOOTTIME) else {
        return String::new();
    };
    let Ok(cur_time_real) = clock_gettime(ClockId::CLOCK_REALTIME) else {
        return String::new();
    };
    let cur_time_boot = Duration::new(
        cur_time_boot.tv_sec() as u64,
        cur_time_boot.tv_nsec() as u32,
    )
    .as_nanos() as i64;
    let diff = cur_time_boot - ktime as i64;
    let cur_time_real = Duration::new(
        cur_time_real.tv_sec() as u64,
        cur_time_real.tv_nsec() as u32,
    )
    .as_nanos() as i64;
    DateTime::from_timestamp_nanos(cur_time_real - diff)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}
