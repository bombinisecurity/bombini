//! Transmutes GTFOBinsEvent to serialized format

use bombini_common::event::gtfobins::GTFOBinsMsg;

use serde::Serialize;

use super::process::Process;
use super::{Transmute, transmute_ktime};

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
    pub fn new(event: GTFOBinsMsg, ktime: u64) -> Self {
        Self {
            process: Process::new(event.process),
            timestamp: transmute_ktime(ktime),
        }
    }
}

impl Transmute for GTFOBinsEvent {}
