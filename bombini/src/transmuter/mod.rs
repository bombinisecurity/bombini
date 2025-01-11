//! Transmuter provides an interface to transmute raw eBPF events into
//! serialized formats

use bombini_common::event::Event;

use gtfobins::GTFOBinsEvent;
use simple::SimpleEvent;

mod gtfobins;
mod simple;

/// Transmutes eBPF events from low representation into serialized formats
pub struct Transmuter;

impl Transmuter {
    /// Transmutes bombini_common::Event into serialized formats
    pub async fn transmute(&self, event: Event) -> Result<Vec<u8>, anyhow::Error> {
        match event {
            Event::Simple(s) => Ok(SimpleEvent::new(s).to_json()?.into_bytes()),
            Event::GTFOBins(s) => Ok(GTFOBinsEvent::new(s).to_json()?.into_bytes()),
        }
    }
}
