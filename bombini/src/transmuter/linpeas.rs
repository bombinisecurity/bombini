//! Transmutes LinPEASEvent to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::Event;
use bombini_common::event::linpeas::{LinPEASAlertKind, LinPEASCategory};

use serde::Serialize;

use super::{Transmuter, cache::process::ProcessCache, process::Process, transmute_ktime};

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum LinPEASKind {
    Behavioral,
    Signature,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum LinPEASCategoryName {
    SuidSgid,
    Capabilities,
    SensitiveFiles,
    SudoCheck,
    ProcessEnum,
    KernelInfo,
    ContainerInfo,
    NetworkInfo,
}

/// LinPEAS enumeration alert
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct LinPEASEvent {
    /// Process information
    process: Arc<Process>,
    /// Parent process information
    parent: Option<Arc<Process>>,
    /// Detection layer kind
    kind: LinPEASKind,
    /// Observed enumeration categories
    categories: Vec<LinPEASCategoryName>,
    /// Number of observed unique categories
    category_count: u8,
    /// Event's date and time
    timestamp: String,
}

impl LinPEASEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        kind: LinPEASKind,
        categories: Vec<LinPEASCategoryName>,
        category_count: u8,
        ktime: u64,
    ) -> Self {
        Self {
            process,
            parent,
            kind,
            categories,
            category_count,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct LinPEASEventTransmuter;

impl Transmuter for LinPEASEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::LinPEAS(event) = event {
            let parent = if let Some(cached_process) = process_cache.get(&event.parent) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "LinPEAS: No parent Process record (pid: {}, start: {}) found in cache",
                    event.parent.pid,
                    transmute_ktime(event.parent.start)
                );
                None
            };
            if let Some(cached_process) = process_cache.get_mut(&event.process) {
                let kind = if event.kind == LinPEASAlertKind::Signature as u8 {
                    LinPEASKind::Signature
                } else {
                    LinPEASKind::Behavioral
                };
                let high_level_event = LinPEASEvent::new(
                    cached_process.process.clone(),
                    parent,
                    kind,
                    decode_mask(event.mask),
                    event.category_count,
                    ktime,
                );
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "LinPEAS: No process pid: {}, start: {} found in cache",
                    event.process.pid,
                    transmute_ktime(event.process.start)
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

fn decode_mask(mask: u8) -> Vec<LinPEASCategoryName> {
    let mut out = Vec::new();
    if mask & (1u8 << LinPEASCategory::SuidSgid as u8) != 0 {
        out.push(LinPEASCategoryName::SuidSgid);
    }
    if mask & (1u8 << LinPEASCategory::Capabilities as u8) != 0 {
        out.push(LinPEASCategoryName::Capabilities);
    }
    if mask & (1u8 << LinPEASCategory::SensitiveFiles as u8) != 0 {
        out.push(LinPEASCategoryName::SensitiveFiles);
    }
    if mask & (1u8 << LinPEASCategory::SudoCheck as u8) != 0 {
        out.push(LinPEASCategoryName::SudoCheck);
    }
    if mask & (1u8 << LinPEASCategory::ProcessEnum as u8) != 0 {
        out.push(LinPEASCategoryName::ProcessEnum);
    }
    if mask & (1u8 << LinPEASCategory::KernelInfo as u8) != 0 {
        out.push(LinPEASCategoryName::KernelInfo);
    }
    if mask & (1u8 << LinPEASCategory::ContainerInfo as u8) != 0 {
        out.push(LinPEASCategoryName::ContainerInfo);
    }
    if mask & (1u8 << LinPEASCategory::NetworkInfo as u8) != 0 {
        out.push(LinPEASCategoryName::NetworkInfo);
    }
    out
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::LinPEASEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_linpeas_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new().append(true).open(&event_ref).unwrap();
        let _ = writeln!(file, "## LinPEAS\n\n```json");
        let schema = schemars::schema_for!(LinPEASEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
