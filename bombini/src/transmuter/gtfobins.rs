//! Transmutes GTFOBinsEvent to serialized format

use bombini_common::event::gtfobins::GTFOBinsMsg;

use serde::Serialize;

use super::process::Process;
use super::Transmute;

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct GTFOBinsEvent {
    /// Process Infro
    process: Process,
}

impl GTFOBinsEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: GTFOBinsMsg) -> Self {
        Self {
            process: Process::new(event.process),
        }
    }
}

impl Transmute for GTFOBinsEvent {}
