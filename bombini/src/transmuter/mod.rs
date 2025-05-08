//! Transmuter provides an interface to transmute raw eBPF events into
//! serialized formats

use bombini_common::event::Event;

use gtfobins::GTFOBinsEvent;
use histfile::HistFileEvent;
use io_uring::IOUringEvent;
use process::ProcessExec;
use process::ProcessExit;
use serde::Serialize;

mod gtfobins;
mod histfile;
mod io_uring;
mod process;

/// Transmutes eBPF events from low representation into serialized formats
pub struct Transmuter;

impl Transmuter {
    /// Transmutes bombini_common::Event into serialized formats
    pub async fn transmute(&self, event: Event) -> Result<Vec<u8>, anyhow::Error> {
        match event {
            Event::ProcExec(s) => Ok(ProcessExec::new(s).to_json()?.into_bytes()),
            Event::ProcExit(s) => Ok(ProcessExit::new(s).to_json()?.into_bytes()),
            Event::GTFOBins(s) => Ok(GTFOBinsEvent::new(s).to_json()?.into_bytes()),
            Event::HistFile(s) => Ok(HistFileEvent::new(s).to_json()?.into_bytes()),
            Event::IOUring(s) => Ok(IOUringEvent::new(s).to_json()?.into_bytes()),
        }
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
