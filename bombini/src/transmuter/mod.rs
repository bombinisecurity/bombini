//! Transmuter provides an interface to transmute raw eBPF events into
//! serialized formats

use bombini_common::event::{Event, GenericEvent};

use chrono::{DateTime, SecondsFormat};
use nix::time::{ClockId, clock_gettime};

use anyhow::anyhow;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

mod file;
mod gtfobins;
mod histfile;
mod io_uring;
mod network;
mod process;

use file::FileEventTransmuter;
use gtfobins::GTFOBinsEventTransmuter;
use histfile::HistFileEventTransmuter;
use io_uring::IOUringEventTransmuter;
use network::NetworkEventTransmuter;
use process::{ProcessEventTransmuter, ProcessExecTransmuter, ProcessExitTransmuter};

pub struct TransmuterRegistry {
    handlers: [Option<Arc<dyn Transmuter>>; 256],
}
impl TransmuterRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            handlers: std::array::from_fn(|_| None),
        };

        registry.handlers[0] = Some(Arc::new(ProcessExecTransmuter));
        registry.handlers[1] = Some(Arc::new(ProcessExitTransmuter));
        registry.handlers[2] = Some(Arc::new(ProcessEventTransmuter));
        registry.handlers[3] = Some(Arc::new(FileEventTransmuter));
        registry.handlers[4] = Some(Arc::new(NetworkEventTransmuter));
        registry.handlers[5] = Some(Arc::new(IOUringEventTransmuter));

        registry.handlers[32] = Some(Arc::new(GTFOBinsEventTransmuter));
        registry.handlers[33] = Some(Arc::new(HistFileEventTransmuter));

        registry
    }

    pub async fn transmute(&self, generic_event: GenericEvent) -> Result<Vec<u8>, anyhow::Error> {
        let event_type = generic_event.msg_code as usize;
        if let Some(handler) = self.handlers[event_type].as_ref() {
            handler
                .transmute(&generic_event.event, generic_event.ktime)
                .await
        } else {
            Err(anyhow!(
                "No transmuter for event type {}",
                generic_event.msg_code
            ))
        }
    }
}

#[async_trait]
pub trait Transmuter: Send + Sync {
    /// Transmutes low-level event to high level and serialized representation
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error>;
}

pub fn str_from_bytes(bytes: &[u8]) -> String {
    if let Some(zero) = bytes.iter().position(|e| *e == 0x0) {
        String::from_utf8_lossy(&bytes[..zero]).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

pub fn transmute_ktime(ktime: u64) -> String {
    let Ok(cur_time_boot) = clock_gettime(ClockId::CLOCK_MONOTONIC) else {
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
