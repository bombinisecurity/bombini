//! Transmutes SimpleEvent to serialized representation

use bombini_common::event::simple::SimpleMsg;

use serde::Serialize;

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct SimpleEvent {
    pub pid: u32,
    pub uid: u32,
}

impl SimpleEvent {
    /// Constructs High level event representation from low eBPF
    pub fn new(event: SimpleMsg) -> Self {
        Self {
            pid: event.pid,
            uid: event.uid,
        }
    }

    /// Get JSON reprsentation
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}
