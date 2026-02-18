use anyhow::bail;
use aya::Ebpf;
use aya::maps::hash_map::HashMap as EbpfHashMap;

use bombini_common::config::rule::{CapKey, CredAttributes, UIDKey};
use bombini_common::event::process::Capabilities;
use bombini_common::{
    config::rule::{Predicate, RuleOp},
    constants::MAX_RULE_OPERATIONS,
};

use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;

use super::PredicateSerializer;
use crate::rule::ast::Literal;

#[derive(Debug)]
pub struct UidPredicate {
    pub predicate: Predicate,
    pub uid_map: HashMap<u32, u8>,
    pub euid_map: HashMap<u32, u8>,
}

impl UidPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            uid_map: HashMap::new(),
            euid_map: HashMap::new(),
        }
    }
}

impl Default for UidPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for UidPredicate {
    fn set_operation(&mut self, idx: u8, op: RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        let values: Result<Vec<u32>, anyhow::Error> = values
            .iter()
            .cloned()
            .map(|lit| match lit {
                Literal::Uint(i) => Ok(i as u32),
                Literal::String(s) => Err(anyhow::anyhow!(
                    "expected Uint literal, found String: {}",
                    s
                )),
            })
            .collect();
        let values = values?;
        match name {
            "uid" => {
                for uid in values {
                    self.uid_map
                        .entry(uid)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(CredAttributes::UID as u8)
            }
            "euid" => {
                for euid in values {
                    self.euid_map
                        .entry(euid)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(CredAttributes::EUID as u8)
            }
            _ => Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
        }
    }

    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_UID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.uid_map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                uid: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }

        let mut euid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_EUID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (euid, value) in self.euid_map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                uid: *euid,
            };
            let _ = euid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_UID_MAP", map_name_prefix),
            self.uid_map.len() as u32,
        );
        map.insert(
            format!("{}_EUID_MAP", map_name_prefix),
            self.euid_map.len() as u32,
        );
        map
    }
}

#[derive(Debug)]
pub struct GidPredicate {
    pub predicate: Predicate,
    pub gid_map: HashMap<u32, u8>,
    pub egid_map: HashMap<u32, u8>,
}

impl GidPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            gid_map: HashMap::new(),
            egid_map: HashMap::new(),
        }
    }
}

impl Default for GidPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for GidPredicate {
    fn set_operation(&mut self, idx: u8, op: RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        let values: Result<Vec<u32>, anyhow::Error> = values
            .iter()
            .cloned()
            .map(|lit| match lit {
                Literal::Uint(i) => Ok(i as u32),
                Literal::String(s) => Err(anyhow::anyhow!(
                    "expected Uint literal, found String: {}",
                    s
                )),
            })
            .collect();
        let values = values?;
        match name {
            "gid" => {
                for gid in values {
                    self.gid_map
                        .entry(gid)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(CredAttributes::GID as u8)
            }
            "egid" => {
                for egid in values {
                    self.egid_map
                        .entry(egid)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(CredAttributes::EGID as u8)
            }
            _ => Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
        }
    }

    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut gid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_GID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (gid, value) in self.gid_map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                uid: *gid,
            };
            let _ = gid_map.insert(key, value, 0);
        }

        let mut egid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_EGID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (egid, value) in self.egid_map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                uid: *egid,
            };
            let _ = egid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_GID_MAP", map_name_prefix),
            self.gid_map.len() as u32,
        );
        map.insert(
            format!("{}_EGID_MAP", map_name_prefix),
            self.egid_map.len() as u32,
        );
        map
    }
}

#[derive(Debug)]
pub struct CapPredicate {
    pub predicate: Predicate,
    pub ecap_map: HashMap<u8, Capabilities>,
    pub pcap_map: HashMap<u8, Capabilities>,
}

impl CapPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            ecap_map: HashMap::new(),
            pcap_map: HashMap::new(),
        }
    }
}

impl Default for CapPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for CapPredicate {
    fn set_operation(&mut self, idx: u8, op: RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        let values: Result<Vec<Capabilities>, anyhow::Error> = values
            .iter()
            .cloned()
            .map(|lit| match lit {
                Literal::String(s) => Capabilities::from_str(&s)
                    .map_err(|x| anyhow::anyhow!("Error while parsing caps: {}", x)),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .collect();
        let caps = values?
            .into_iter()
            .fold(Capabilities::empty(), |a, b| a | b);
        match name {
            "ecaps" => {
                if self.ecap_map.insert(in_idx, caps).is_some() {
                    bail!("ecaps already set for index {}", in_idx);
                }
                Ok(CredAttributes::ECAPS as u8)
            }
            "pcaps" => {
                if self.pcap_map.insert(in_idx, caps).is_some() {
                    bail!("ecaps already set for index {}", in_idx);
                }
                Ok(CredAttributes::PCAPS as u8)
            }
            _ => Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
        }
    }

    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ecap_map: EbpfHashMap<_, CapKey, Capabilities> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ECAP_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.ecap_map.iter() {
            let key = CapKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = ecap_map.insert(key, value, 0);
        }

        let mut pcap_map: EbpfHashMap<_, CapKey, Capabilities> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_PCAP_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.pcap_map.iter() {
            let key = CapKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = pcap_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_ECAP_MAP", map_name_prefix),
            self.ecap_map.len() as u32,
        );
        map.insert(
            format!("{}_PCAP_MAP", map_name_prefix),
            self.pcap_map.len() as u32,
        );
        map
    }
}

#[derive(Debug)]
pub struct CredPredicate {
    pub predicate: Predicate,
    pub ecap_map: HashMap<u8, Capabilities>,
    pub euid_map: HashMap<u32, u8>,
}

impl CredPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            ecap_map: HashMap::new(),
            euid_map: HashMap::new(),
        }
    }
}

impl Default for CredPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for CredPredicate {
    fn set_operation(&mut self, idx: u8, op: RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        match name {
            "ecaps" => {
                let values: Result<Vec<Capabilities>, anyhow::Error> = values
                    .iter()
                    .cloned()
                    .map(|lit| match lit {
                        Literal::String(s) => Capabilities::from_str(&s)
                            .map_err(|x| anyhow::anyhow!("Error while parsing caps: {}", x)),
                        Literal::Uint(i) => Err(anyhow::anyhow!(
                            "expected String literal, found Uint: {}",
                            i
                        )),
                    })
                    .collect();
                let caps = values?
                    .into_iter()
                    .fold(Capabilities::empty(), |a, b| a | b);

                if self.ecap_map.insert(in_idx, caps).is_some() {
                    bail!("ecaps already set for index {}", in_idx);
                }
                Ok(CredAttributes::ECAPS as u8)
            }
            "euid" => {
                let values: Result<Vec<u32>, anyhow::Error> = values
                    .iter()
                    .cloned()
                    .map(|lit| match lit {
                        Literal::Uint(i) => Ok(i as u32),
                        Literal::String(s) => Err(anyhow::anyhow!(
                            "expected Uint literal, found Strinng: {}",
                            s
                        )),
                    })
                    .collect();
                let values = values?;
                for euid in values {
                    self.euid_map
                        .entry(euid)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(CredAttributes::EUID as u8)
            }
            _ => Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
        }
    }

    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ecap_map: EbpfHashMap<_, CapKey, Capabilities> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ECAP_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.ecap_map.iter() {
            let key = CapKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = ecap_map.insert(key, value, 0);
        }

        let mut euid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_EUID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (euid, value) in self.euid_map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                uid: *euid,
            };
            let _ = euid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_ECAP_MAP", map_name_prefix),
            self.ecap_map.len() as u32,
        );
        map.insert(
            format!("{}_EUID_MAP", map_name_prefix),
            self.euid_map.len() as u32,
        );
        map
    }
}
