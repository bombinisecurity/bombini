//! Transmutes GTFOBinsEvent to serialized format

use anyhow::anyhow;
use async_trait::async_trait;

use bombini_common::event::{Event, gtfobins::GTFOBinsMsg};

use serde::Serialize;

use super::process::Process;
use super::{Transmuter, transmute_ktime};

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct GTFOBinsEvent {
    /// Process Infro
    process: Process,
    /// Event's date and time
    timestamp: String,
}

impl GTFOBinsEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &GTFOBinsMsg, ktime: u64) -> Self {
        Self {
            process: Process::new(event.process),
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct GTFOBinsEventTransmuter;

#[async_trait]
impl Transmuter for GTFOBinsEventTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::GTFOBins(event) = event {
            let high_level_event = GTFOBinsEvent::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}
