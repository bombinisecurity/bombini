//! Transmutes GTFOBinsEvent to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::Event;

use serde::Serialize;

use super::{Transmuter, cache::process::ProcessCache, process::Process, transmute_ktime};

/// GTFO binary event execution attempt
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GTFOBinsEvent {
    /// Process information
    process: Arc<Process>,
    /// Event's date and time
    timestamp: String,
}

impl GTFOBinsEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(process: Arc<Process>, ktime: u64) -> Self {
        Self {
            process,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct GTFOBinsEventTransmuter;

impl Transmuter for GTFOBinsEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::GTFOBins(event) = event {
            if let Some(cached_process) = process_cache.get_mut(&event.process) {
                let high_level_event = GTFOBinsEvent::new(cached_process.process.clone(), ktime);
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "GTFOBins: No process pid: {}, start: {} found in cache",
                    event.process.pid,
                    transmute_ktime(event.process.start)
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::GTFOBinsEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_gtfobins_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&event_ref)
            .unwrap();
        let _ = writeln!(file, "## GTFOBins\n\n```json");
        let schema = schemars::schema_for!(GTFOBinsEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
