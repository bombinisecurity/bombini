//! Transmutes KernelEvent to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::{
    Event,
    kernel::{BpfMapType, BpfProgType, KernelEventVariant},
};

use serde::Serialize;

use crate::proto::config::{HookConfig, KernelMonConfig};

use super::{Transmuter, cache::process::ProcessCache, process::Process, transmute_ktime};

/// Kernel Event
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct KernelEvent<'a> {
    /// Process information
    process: Arc<Process>,
    /// Parent process information
    parent: Option<Arc<Process>>,
    /// If event is blocked by sandbox mode
    blocked: bool,
    /// Kernel event
    kernel_event: KernelEventType,
    /// Event's date and time
    timestamp: String,
    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum KernelEventType {
    BpfMapAccess(BpfMapAccessInfo),
    BpfMapCreate(BpfMapCreateInfo),
    BpfProgAccess(BpfProgAccessInfo),
    BpfProgLoad(BpfProgLoadInfo),
}

/// BPF map access information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BpfMapAccessInfo {
    /// BPF map ID
    id: u32,
    /// BPF map name
    name: String,
    /// BPF map type
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    map_type: BpfMapType,
    /// Access mode
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    access_mode: bombini_common::event::file::AccessMode,
}

/// BPF map access information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BpfMapCreateInfo {
    /// BPF map name
    name: String,
    /// BPF map type
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    map_type: BpfMapType,
    /// BPF map key size
    key_size: u32,
    /// BPF map value size
    value_size: u32,
    /// BPF map max entries
    max_entries: u32,
}

/// BPF program access information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BpfProgAccessInfo {
    /// BPF prog ID
    id: u32,
    /// BPF prog name
    name: String,
    /// BPF prog type
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    prog_type: BpfProgType,
    /// hook if available
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<String>,
}

/// BPF program loading information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BpfProgLoadInfo {
    /// BPF prog name
    name: String,
    /// BPF prog type
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    prog_type: BpfProgType,
}

impl<'a> KernelEvent<'a> {
    /// Constructs High level event representation from low eBPF message
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        blocked: bool,
        event: &KernelEventVariant,
        rule: Option<&'a str>,
        ktime: u64,
    ) -> Self {
        let kernel_event = match event {
            KernelEventVariant::BpfMapAccess(info) => {
                KernelEventType::BpfMapAccess(BpfMapAccessInfo {
                    id: info.id,
                    name: super::str_from_bytes(&info.name),
                    map_type: info.map_type,
                    access_mode: info.access_mode,
                })
            }
            KernelEventVariant::BpfMapCreate(info) => {
                KernelEventType::BpfMapCreate(BpfMapCreateInfo {
                    name: super::str_from_bytes(&info.name),
                    map_type: info.map_type,
                    key_size: info.key_size,
                    value_size: info.value_size,
                    max_entries: info.max_entries,
                })
            }
            KernelEventVariant::BpfProgAccess(info) => {
                KernelEventType::BpfProgAccess(BpfProgAccessInfo {
                    id: info.id,
                    name: super::str_from_bytes(&info.name),
                    prog_type: info.prog_type,
                    hook: {
                        let hook = super::str_from_bytes(&info.hook);
                        if hook.is_empty() { None } else { Some(hook) }
                    },
                })
            }
            KernelEventVariant::BpfProgLoad(info) => {
                KernelEventType::BpfProgLoad(BpfProgLoadInfo {
                    name: super::str_from_bytes(&info.name),
                    prog_type: info.prog_type,
                })
            }
        };
        Self {
            process,
            parent,
            blocked,
            rule,
            kernel_event,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct KernelEventTransmuter {
    bpf_map_rule_names: Vec<String>,
    bpf_map_create_rule_names: Vec<String>,
    bpf_prog_rule_names: Vec<String>,
    bpf_prog_load_rule_names: Vec<String>,
}

impl KernelEventTransmuter {
    pub fn new(cfg: &KernelMonConfig) -> Self {
        #[inline(always)]
        fn rule_names_from_hook_config(hook: &Option<HookConfig>) -> Vec<String> {
            hook.as_ref().map_or(Vec::new(), |hcfg| {
                hcfg.rules.iter().map(|x| x.name.clone()).collect()
            })
        }

        Self {
            bpf_map_rule_names: rule_names_from_hook_config(&cfg.bpf_map),
            bpf_map_create_rule_names: rule_names_from_hook_config(&cfg.bpf_map_create),
            bpf_prog_rule_names: rule_names_from_hook_config(&cfg.bpf_prog),
            bpf_prog_load_rule_names: rule_names_from_hook_config(&cfg.bpf_prog_load),
        }
    }

    fn get_rule_name(
        &self,
        kernel_event: &KernelEventVariant,
        rule_idx: Option<u8>,
    ) -> Result<Option<&str>, anyhow::Error> {
        let rule_names = match kernel_event {
            KernelEventVariant::BpfMapAccess(_) => &self.bpf_map_rule_names,
            KernelEventVariant::BpfMapCreate(_) => &self.bpf_map_create_rule_names,
            KernelEventVariant::BpfProgAccess(_) => &self.bpf_prog_rule_names,
            KernelEventVariant::BpfProgLoad(_) => &self.bpf_prog_load_rule_names,
        };

        rule_idx
            .map(|idx| {
                rule_names
                    .get(idx as usize)
                    .map(|x| x.as_str())
                    .ok_or(anyhow::anyhow!(
                        "KernelEvent: No rule name found for rule index: {}",
                        idx
                    ))
            })
            .transpose()
    }
}

impl Transmuter for KernelEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::Kernel(msg) = event {
            let parent = if let Some(cached_process) = process_cache.get(&msg.parent) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "KernelEvent: No parent Process record (pid: {}, start: {}) found in cache",
                    msg.parent.pid,
                    transmute_ktime(msg.parent.start)
                );
                None
            };
            if let Some(cached_process) = process_cache.get_mut(&msg.process) {
                let rule_name = match self.get_rule_name(&msg.event, msg.rule_idx) {
                    Ok(rule_name) => rule_name,
                    Err(e) => {
                        log::warn!("Could not determine rule name, error: {e}");
                        None
                    }
                };
                let high_level_event = KernelEvent::new(
                    cached_process.process.clone(),
                    parent,
                    msg.blocked,
                    &msg.event,
                    rule_name,
                    ktime,
                );
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "KernelEvent: No process (pid: {}, start: {}) found in cache",
                    msg.process.pid,
                    transmute_ktime(msg.process.start)
                ))
            }
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::KernelEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_kernel_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&event_ref)
            .unwrap();
        let _ = writeln!(file, "## KernelMon\n\n```json");
        let schema = schemars::schema_for!(KernelEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
