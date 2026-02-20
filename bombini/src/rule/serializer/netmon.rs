use aya::Ebpf;
use aya::maps::{
    HashMap as EbpfHashMap,
    lpm_trie::{Key, LpmTrie},
};

use bombini_common::{
    config::rule::{ConnectionAttributes, Ipv4MapKey, Ipv6MapKey, PortKey, Predicate, RuleOp},
    constants::MAX_RULE_OPERATIONS,
};

use std::{
    collections::HashMap,
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::PredicateSerializer;
use crate::rule::ast::Literal;

#[derive(Debug)]
pub struct TcpConnectionPredicate {
    pub predicate: Predicate,
    pub ipv4_src_map: HashMap<String, u8>,
    pub ipv4_dst_map: HashMap<String, u8>,
    pub ipv6_src_map: HashMap<String, u8>,
    pub ipv6_dst_map: HashMap<String, u8>,
    pub port_src_map: HashMap<u16, u8>,
    pub port_dst_map: HashMap<u16, u8>,
}

impl TcpConnectionPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            ipv4_src_map: HashMap::new(),
            ipv4_dst_map: HashMap::new(),
            ipv6_src_map: HashMap::new(),
            ipv6_dst_map: HashMap::new(),
            port_src_map: HashMap::new(),
            port_dst_map: HashMap::new(),
        }
    }
}

impl Default for TcpConnectionPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for TcpConnectionPredicate {
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
        if name.starts_with("port_") {
            let values: Result<Vec<u16>, anyhow::Error> = values
                .iter()
                .map(|lit| match lit {
                    Literal::Uint(i) => {
                        if *i > 65535 {
                            Err(anyhow::anyhow!("port value: {} must be <= 65535", i))
                        } else {
                            Ok(*i as u16)
                        }
                    }
                    Literal::String(s) => Err(anyhow::anyhow!(
                        "expected Uint literal, found String: {}",
                        s
                    )),
                })
                .collect();
            let values = values?;
            match name {
                "port_src" => {
                    for port in values {
                        self.port_src_map
                            .entry(port)
                            .and_modify(|value| *value |= 1 << in_idx)
                            .or_insert(1 << in_idx);
                    }
                    return Ok(ConnectionAttributes::PortSrc as u8);
                }
                "port_dst" => {
                    for port in values {
                        self.port_dst_map
                            .entry(port)
                            .and_modify(|value| *value |= 1 << in_idx)
                            .or_insert(1 << in_idx);
                    }
                    return Ok(ConnectionAttributes::PortDst as u8);
                }
                _ => return Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
            }
        }

        // CIDR processing
        let values: Result<Vec<String>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .collect();
        let values = values?;
        match name {
            "ipv4_src" => {
                for cidr in values {
                    self.ipv4_src_map
                        .entry(cidr)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ConnectionAttributes::Ipv4Src as u8)
            }
            "ipv4_dst" => {
                for cidr in values {
                    self.ipv4_dst_map
                        .entry(cidr)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ConnectionAttributes::Ipv4Dst as u8)
            }
            "ipv6_src" => {
                for cidr in values {
                    self.ipv6_src_map
                        .entry(cidr)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ConnectionAttributes::Ipv6Src as u8)
            }
            "ipv6_dst" => {
                for cidr in values {
                    self.ipv6_dst_map
                        .entry(cidr)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ConnectionAttributes::Ipv6Dst as u8)
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
        let mut ipv4_src_map: LpmTrie<_, Ipv4MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_SRC_IPV4_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.ipv4_src_map.iter() {
            let mut key = Ipv4MapKey {
                rule_idx,
                ip_addr: [0u8; 4],
            };
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let mask = if parts.len() == 2 {
                let mask = parts[1].parse::<u32>()?;
                if mask > 32 {
                    return Err(anyhow::anyhow!(
                        "IPv4 address mask must be equal or less 32. CIDR: {}",
                        cidr_str
                    ));
                }
                mask + 8
            } else {
                std::mem::size_of::<Ipv4MapKey>() as u32 * 8 // 32 bits + 8 bits for rule idx
            };
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                key.ip_addr = ip.octets();
            } else {
                return Err(anyhow::anyhow!("Coudn't parse Ipv4 address: {}", cidr_str));
            }
            let map_key = Key::new(mask, key);
            let _ = ipv4_src_map.insert(&map_key, value, 0);
        }

        let mut ipv4_dst_map: LpmTrie<_, Ipv4MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_DST_IPV4_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.ipv4_dst_map.iter() {
            let mut key = Ipv4MapKey {
                rule_idx,
                ip_addr: [0u8; 4],
            };
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let mask = if parts.len() == 2 {
                let mask = parts[1].parse::<u32>()?;
                if mask > 32 {
                    return Err(anyhow::anyhow!(
                        "IPv4 address mask must be equal or less 32. CIDR: {}",
                        cidr_str
                    ));
                }
                mask + 8
            } else {
                std::mem::size_of::<Ipv4MapKey>() as u32 * 8 // 32 bits + 8 bits for rule idx
            };
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                key.ip_addr = ip.octets();
            } else {
                return Err(anyhow::anyhow!("Coudn't parse Ipv4 address: {}", cidr_str));
            }
            let map_key = Key::new(mask, key);
            let _ = ipv4_dst_map.insert(&map_key, value, 0);
        }

        let mut ipv6_src_map: LpmTrie<_, Ipv6MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_SRC_IPV6_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.ipv6_src_map.iter() {
            let mut key = Ipv6MapKey {
                rule_idx,
                ip_addr: [0u8; 16],
            };
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let mask = if parts.len() == 2 {
                let mask = parts[1].parse::<u32>()?;
                if mask > 128 {
                    return Err(anyhow::anyhow!(
                        "IPv6 address mask must be equal or less 128. CIDR: {}",
                        cidr_str
                    ));
                }
                mask + 8
            } else {
                std::mem::size_of::<Ipv6MapKey>() as u32 * 8 //  16 octets + 8 bits for rule idx
            };
            if let Ok(ip) = parts[0].parse::<Ipv6Addr>() {
                key.ip_addr = ip.octets();
            } else {
                return Err(anyhow::anyhow!("Coudn't parse Ipv6 address: {}", cidr_str));
            }
            let map_key = Key::new(mask, key);
            let _ = ipv6_src_map.insert(&map_key, value, 0);
        }

        let mut ipv6_dst_map: LpmTrie<_, Ipv6MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_DST_IPV6_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.ipv6_dst_map.iter() {
            let mut key = Ipv6MapKey {
                rule_idx,
                ip_addr: [0u8; 16],
            };
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let mask = if parts.len() == 2 {
                let mask = parts[1].parse::<u32>()?;
                if mask > 128 {
                    return Err(anyhow::anyhow!(
                        "IPv6 address mask must be equal or less 128. CIDR: {}",
                        cidr_str
                    ));
                }
                mask + 8
            } else {
                std::mem::size_of::<Ipv6MapKey>() as u32 * 8 //  16 octets + 8 bits for rule idx
            };
            if let Ok(ip) = parts[0].parse::<Ipv6Addr>() {
                key.ip_addr = ip.octets();
            } else {
                return Err(anyhow::anyhow!("Coudn't parse Ipv6 address: {}", cidr_str));
            }
            let map_key = Key::new(mask, key);
            let _ = ipv6_dst_map.insert(&map_key, value, 0);
        }

        let mut port_src_map: EbpfHashMap<_, PortKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_SRC_PORT_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (port, value) in self.port_src_map.iter() {
            let key = PortKey {
                rule_idx: rule_idx as u16,
                port: *port,
            };
            let _ = port_src_map.insert(key, value, 0);
        }

        let mut port_dst_map: EbpfHashMap<_, PortKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_DST_PORT_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (port, value) in self.port_dst_map.iter() {
            let key = PortKey {
                rule_idx: rule_idx as u16,
                port: *port,
            };
            let _ = port_dst_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_SRC_IPV4_MAP", map_name_prefix),
            self.ipv4_src_map.len() as u32,
        );
        map.insert(
            format!("{}_DST_IPV4_MAP", map_name_prefix),
            self.ipv4_dst_map.len() as u32,
        );
        map.insert(
            format!("{}_SRC_IPV6_MAP", map_name_prefix),
            self.ipv6_src_map.len() as u32,
        );
        map.insert(
            format!("{}_DST_IPV6_MAP", map_name_prefix),
            self.ipv6_dst_map.len() as u32,
        );
        map.insert(
            format!("{}_SRC_PORT_MAP", map_name_prefix),
            self.port_src_map.len() as u32,
        );
        map.insert(
            format!("{}_DST_PORT_MAP", map_name_prefix),
            self.port_dst_map.len() as u32,
        );
        map
    }
}
