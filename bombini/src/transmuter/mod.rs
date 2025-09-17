//! Transmuter provides an interface to transmute raw eBPF events into
//! serialized formats

use bombini_common::event::{Event, GenericEvent};

use file::FileEvent;
use gtfobins::GTFOBinsEvent;
use histfile::HistFileEvent;
use io_uring::IOUringEvent;
use network::NetworkEvent;

use chrono::{DateTime, SecondsFormat};
use nix::time::{clock_gettime, ClockId};
use serde::Serialize;

use std::time::Duration;

use crate::transmuter::process::ProcessPrctl;
use process::{
    ProcessCapset, ProcessCreateUserNs, ProcessExec, ProcessExit, ProcessPtraceAccessCheck,
    ProcessSetUid,
};

mod file;
mod gtfobins;
mod histfile;
mod io_uring;
mod network;
mod process;

/// Transmutes eBPF events from low representation into serialized formats
pub struct Transmuter;

macro_rules! transmute {
    ($event:expr, $ktime:expr, $(($key:path, $type:ty)),+) => {
        match $event {
            $($key(s) => Ok(<$type>::new(s, $ktime)
            .to_json()?
            .into_bytes()),)+
        }
    };
}
impl Transmuter {
    /// Transmutes bombini_common::Event into serialized formats
    pub async fn transmute(&self, generic_event: GenericEvent) -> Result<Vec<u8>, anyhow::Error> {
        transmute!(
            generic_event.event,
            generic_event.ktime,
            /*Low-level event -> High-level event representation */
            (Event::ProcExec, ProcessExec),
            (Event::ProcExit, ProcessExit),
            (Event::ProcSetUid, ProcessSetUid),
            (Event::ProcCapset, ProcessCapset),
            (Event::ProcPrctl, ProcessPrctl),
            (Event::ProcCreateUserNs, ProcessCreateUserNs),
            (Event::ProcPtraceAccessCheck, ProcessPtraceAccessCheck),
            (Event::File, FileEvent),
            (Event::GTFOBins, GTFOBinsEvent),
            (Event::HistFile, HistFileEvent),
            (Event::IOUring, IOUringEvent),
            (Event::Network, NetworkEvent)
        )
    }
}

trait Transmute {
    /// Get JSON reprsentation
    fn to_json(&self) -> Result<String, serde_json::Error>
    where
        Self: Serialize,
    {
        serde_json::to_string(&self)
    }
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
