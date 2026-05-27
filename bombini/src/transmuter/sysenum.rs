//! Transmutes SysEnumMon events to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::Event;

use serde::Serialize;

use super::{
    Transmuter, cache::process::ProcessCache, process::Process, str_from_bytes, transmute_ktime,
};

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChainEntry {
    name: String,
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SysEnumMonEvent {
    process: Arc<Process>,
    parent: Option<Arc<Process>>,
    chain: Vec<ChainEntry>,
    timestamp: String,
}

impl SysEnumMonEvent {
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        chain: Vec<ChainEntry>,
        ktime: u64,
    ) -> Self {
        Self {
            process,
            parent,
            chain,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct SysEnumMonEventTransmuter;

impl Transmuter for SysEnumMonEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let Event::SysEnum(event) = event else {
            return Err(anyhow!("Unexpected event variant"));
        };
        let parent = if let Some(cached_process) = process_cache.get(&event.parent) {
            Some(cached_process.process.clone())
        } else {
            log::debug!(
                "SysEnumMon: No parent Process record (pid: {}, start: {}) found in cache",
                event.parent.pid,
                transmute_ktime(event.parent.start)
            );
            None
        };
        let cached_process = process_cache.get_mut(&event.process).ok_or_else(|| {
            anyhow!(
                "SysEnumMon: No process pid: {}, start: {} found in cache",
                event.process.pid,
                transmute_ktime(event.process.start)
            )
        })?;
        let chain_len = (event.chain_len as usize).min(event.chain.len());
        let chain = event
            .chain
            .iter()
            .take(chain_len)
            .map(|item| ChainEntry {
                name: str_from_bytes(&item.name),
                timestamp: transmute_ktime(item.timestamp_ns),
            })
            .collect();
        let high_level_event =
            SysEnumMonEvent::new(cached_process.process.clone(), parent, chain, ktime);
        Ok(serde_json::to_vec(&high_level_event)?)
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::SysEnumMonEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_sysenummon_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new().append(true).open(&event_ref).unwrap();
        let _ = writeln!(file, "## SysEnumMon\n\n```json");
        let schema = schemars::schema_for!(SysEnumMonEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
