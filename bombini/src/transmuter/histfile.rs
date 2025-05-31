//! Transmutes HistFileEvent to serialized format

use bombini_common::event::histfile::HistFileMsg;

use serde::Serialize;

use super::process::Process;
use super::{str_from_bytes, transmute_ktime, Transmute};

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
    pub fn new(event: HistFileMsg, ktime: u64) -> Self {
        Self {
            process: Process::new(event.process),
            command: str_from_bytes(&event.command),
            timestamp: transmute_ktime(ktime),
        }
    }
}

impl Transmute for HistFileEvent {}
