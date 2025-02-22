//! Transmutes GTFOBinsEvent to serialized format

use bombini_common::event::gtfobins::GTFOBinsMsg;

use serde::Serialize;

use super::process::Process;

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct GTFOBinsEvent {
    /// Process Infro
    process: Process,
}

impl GTFOBinsEvent {
    /// Constructs High level event representation from low eBPF
    pub fn new(event: GTFOBinsMsg) -> Self {
        Self {
            process: Process::new(event.process),
        }
    }

    /// Get JSON reprsentation
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}
