//! Transmutes NetworkEvent to serialized format

use anyhow::anyhow;
use std::sync::Arc;

use bombini_common::event::{
    Event,
    network::{NetworkEventVariant, TcpConnectionV4, TcpConnectionV6},
};
use serde::Serialize;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::proto::config::{HookConfig, NetMonConfig};

use super::{Transmuter, cache::process::ProcessCache, process::Process, transmute_ktime};

/// Network event
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct NetworkEvent<'a> {
    /// Process information
    process: Arc<Process>,
    /// Parent process information
    parent: Option<Arc<Process>>,
    /// Network event
    network_event: NetworkEventType,
    /// Event's date and time
    timestamp: String,
    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum NetworkEventType {
    TcpConnectionEstablish(TcpConnection),
    TcpConnectionClose(TcpConnection),
    TcpConnectionAccept(TcpConnection),
}

/// TCP IPv4 connection information
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(C)]
pub struct TcpConnection {
    /// source IP address
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    saddr: IpAddr,
    /// destination IP address,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    daddr: IpAddr,
    /// source port
    sport: u16,
    /// destination port
    dport: u16,
    /// socket cookie
    cookie: u64,
}

impl<'a> NetworkEvent<'a> {
    /// Constructs High level event representation from low eBPF message
    pub fn new(
        process: Arc<Process>,
        parent: Option<Arc<Process>>,
        event: &NetworkEventVariant,
        rule: Option<&'a str>,
        ktime: u64,
    ) -> Self {
        match event {
            NetworkEventVariant::TcpConV4Establish(con) => {
                let con_event = transmute_connection_v4(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionEstablish(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkEventVariant::TcpConV6Establish(con) => {
                let con_event = transmute_connection_v6(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionEstablish(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkEventVariant::TcpConV4Close(con) => {
                let con_event = transmute_connection_v4(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionClose(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkEventVariant::TcpConV6Close(con) => {
                let con_event = transmute_connection_v6(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionClose(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkEventVariant::TcpConV4Accept(con) => {
                let con_event = transmute_connection_v4(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionAccept(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkEventVariant::TcpConV6Accept(con) => {
                let con_event = transmute_connection_v6(con);
                Self {
                    process,
                    parent,
                    rule,
                    network_event: NetworkEventType::TcpConnectionAccept(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
        }
    }
}

fn transmute_connection_v4(con: &TcpConnectionV4) -> TcpConnection {
    let s: [u8; 4] = Ipv4Addr::from_bits(con.saddr).octets();
    let d: [u8; 4] = Ipv4Addr::from_bits(con.daddr).octets();
    TcpConnection {
        saddr: IpAddr::V4(Ipv4Addr::new(s[3], s[2], s[1], s[0])),
        daddr: IpAddr::V4(Ipv4Addr::new(d[3], d[2], d[1], d[0])),
        sport: con.sport,
        dport: con.dport,
        cookie: con.cookie,
    }
}

fn transmute_connection_v6(con: &TcpConnectionV6) -> TcpConnection {
    TcpConnection {
        saddr: IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(con.saddr))),
        daddr: IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(con.daddr))),
        sport: con.sport,
        dport: con.dport,
        cookie: con.cookie,
    }
}

pub struct NetworkEventTransmuter {
    ingress_rule_names: Vec<String>,
    egress_rule_names: Vec<String>,
}

impl NetworkEventTransmuter {
    pub fn new(cfg: &NetMonConfig) -> Self {
        #[inline(always)]
        fn rule_names_from_hook_config(hook: &Option<HookConfig>) -> Vec<String> {
            hook.as_ref().map_or(Vec::new(), |hcfg| {
                hcfg.rules.iter().map(|x| x.name.clone()).collect()
            })
        }

        Self {
            ingress_rule_names: rule_names_from_hook_config(&cfg.ingress),
            egress_rule_names: rule_names_from_hook_config(&cfg.egress),
        }
    }

    fn get_rule_name(
        &self,
        netmon_event: &NetworkEventVariant,
        rule_idx: Option<u8>,
    ) -> Result<Option<&str>, anyhow::Error> {
        let rule_names = match netmon_event {
            NetworkEventVariant::TcpConV4Establish(_)
            | NetworkEventVariant::TcpConV6Establish(_) => &self.egress_rule_names,
            NetworkEventVariant::TcpConV4Close(_) | NetworkEventVariant::TcpConV6Close(_) => {
                // Could be either ingress or egress
                return Ok(None);
            }
            NetworkEventVariant::TcpConV4Accept(_) | NetworkEventVariant::TcpConV6Accept(_) => {
                &self.ingress_rule_names
            }
        };

        rule_idx
            .map(|idx| {
                rule_names
                    .get(idx as usize)
                    .map(|x| x.as_str())
                    .ok_or(anyhow::anyhow!(
                        "NetworkEvent: No rule name found for rule index: {}",
                        idx
                    ))
            })
            .transpose()
    }
}

impl Transmuter for NetworkEventTransmuter {
    fn transmute(
        &self,
        event: &Event,
        ktime: u64,
        process_cache: &mut ProcessCache,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::Network(msg) = event {
            let parent = if let Some(cached_process) = process_cache.get(&msg.parent) {
                Some(cached_process.process.clone())
            } else {
                log::debug!(
                    "NetworkEvent: No parent Process record (pid: {}, start: {}) found in cache",
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
                let high_level_event = NetworkEvent::new(
                    cached_process.process.clone(),
                    parent,
                    &msg.event,
                    rule_name,
                    ktime,
                );
                Ok(serde_json::to_vec(&high_level_event)?)
            } else {
                Err(anyhow!(
                    "NetworkEvent: No process (pid: {}, start: {}) found in cache",
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
    use super::NetworkEvent;
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
        let _ = writeln!(file, "## NetMon\n\n```json");
        let schema = schemars::schema_for!(NetworkEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
