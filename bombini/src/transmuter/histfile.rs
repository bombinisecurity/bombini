//! Transmutes HistFileEvent to serialized format

use anyhow::anyhow;
use async_trait::async_trait;

use bombini_common::event::{Event, histfile::HistFileMsg};

use serde::Serialize;

use super::process::Process;
use super::{Transmuter, str_from_bytes, transmute_ktime};

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct HistFileEvent {
    /// bash process Infro
    process: Process,
    /// bash command
    pub command: String,
    /// Event's date and time
    timestamp: String,
}

impl HistFileEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &HistFileMsg, ktime: u64) -> Self {
        Self {
            process: Process::new(event.process),
            command: str_from_bytes(&event.command),
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct HistFileEventTransmuter;

#[async_trait]
impl Transmuter for HistFileEventTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::HistFile(event) = event {
            let high_level_event = HistFileEvent::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}
