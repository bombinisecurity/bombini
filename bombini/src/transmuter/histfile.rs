//! Transmutes HistFileEvent to serialized format

use bombini_common::event::histfile::HistFileMsg;

use serde::Serialize;

use super::process::Process;
use super::{str_from_bytes, Transmute};

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct HistFileEvent {
    /// bash process Infro
    process: Process,
    /// bash command
    pub command: String,
}

impl HistFileEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: HistFileMsg) -> Self {
        Self {
            process: Process::new(event.process),
            command: str_from_bytes(&event.command),
        }
    }
}

impl Transmute for HistFileEvent {}
