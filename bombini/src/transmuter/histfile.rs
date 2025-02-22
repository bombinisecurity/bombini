//! Transmutes HistFileEvent to serialized format

use bombini_common::event::histfile::HistFileMsg;

use serde::Serialize;

use super::process::Process;

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
    /// Constructs High level event representation from low eBPF
    pub fn new(event: HistFileMsg) -> Self {
        let command = if *event.command.last().unwrap() == 0x0 {
            let zero = event.command.iter().position(|e| *e == 0x0).unwrap();
            String::from_utf8_lossy(&event.command[..zero]).to_string()
        } else {
            String::from_utf8_lossy(&event.command).to_string()
        };
        Self {
            process: Process::new(event.process),
            command,
        }
    }

    /// Get JSON reprsentation
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}
