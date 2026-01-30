use aya::Ebpf;
use aya::maps::{
    hash_map::HashMap as EbpfHashMap,
    lpm_trie::{Key, LpmTrie},
};

use bombini_common::{
    config::rule::{
        FileNameMapKey, PathMapKey, PathPrefixMapKey, Predicate, RuleOp, ScopeAttributes,
    },
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, MAX_RULE_OPERATIONS},
};

use std::collections::HashMap;

use super::PredicateSerializer;
use crate::ast::Literal;

pub struct ScopePredicate {
    pub predicate: Predicate,
    pub binary_path_map: HashMap<String, u8>,
    pub binary_prefix_map: HashMap<String, u8>,
    pub binary_name_map: HashMap<String, u8>,
}

impl ScopePredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            binary_name_map: HashMap::new(),
            binary_path_map: HashMap::new(),
            binary_prefix_map: HashMap::new(),
        }
    }
}

impl Default for ScopePredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for ScopePredicate {
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
            "binary_path" => {
                for path in values {
                    self.binary_path_map
                        .entry(path)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ScopeAttributes::BinaryPath as u8)
            }
            "binary_name" => {
                for name in values {
                    self.binary_name_map
                        .entry(name)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ScopeAttributes::BinaryName as u8)
            }
            "binary_prefix" => {
                for prefix in values {
                    self.binary_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(ScopeAttributes::BinaryPrefix as u8)
            }
            _ => Err(anyhow::anyhow!("invalid scope attribute name: {}", name)),
        }
    }

    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut bpath_map: EbpfHashMap<_, PathMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_BINPATH_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (path, value) in self.binary_path_map.iter() {
            let mut key = PathMapKey {
                rule_idx,
                path: [0u8; MAX_FILE_PATH],
            };
            let path_bytes = path.as_bytes();
            let len = path_bytes.len();
            if len < MAX_FILE_PATH {
                key.path[..len].clone_from_slice(path_bytes);
            } else {
                key.path.clone_from_slice(&path_bytes[..MAX_FILE_PATH]);
            }
            let _ = bpath_map.insert(key, value, 0);
        }

        let mut bname_map: EbpfHashMap<_, FileNameMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_BINNAME_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (name, value) in self.binary_name_map.iter() {
            let mut key = FileNameMapKey {
                rule_idx,
                name: [0u8; MAX_FILENAME_SIZE],
            };
            let name_bytes = name.as_bytes();
            let len = name_bytes.len();
            if len < MAX_FILENAME_SIZE {
                key.name[..len].clone_from_slice(name_bytes);
            } else {
                key.name.clone_from_slice(&name_bytes[..MAX_FILENAME_SIZE]);
            }
            let _ = bname_map.insert(key, value, 0);
        }

        let mut bprefix_map: LpmTrie<_, PathPrefixMapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_BINPREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.binary_prefix_map.iter() {
            let mut key = PathPrefixMapKey {
                rule_idx,
                path_prefix: [0u8; MAX_FILE_PREFIX],
            };
            let prefix_bytes = prefix.as_bytes();
            let len = prefix_bytes.len();
            if len < MAX_FILE_PREFIX {
                key.path_prefix[..len].clone_from_slice(prefix_bytes);
            } else {
                key.path_prefix
                    .clone_from_slice(&prefix_bytes[..MAX_FILE_PREFIX]);
            }
            let map_key = Key::new(((prefix.len() + 1) * 8) as u32, key);
            let _ = bprefix_map.insert(&map_key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_BINPREFIX_MAP", map_name_prefix),
            self.binary_prefix_map.len() as u32,
        );
        map.insert(
            format!("{}_BINPATH_MAP", map_name_prefix),
            self.binary_path_map.len() as u32,
        );
        map.insert(
            format!("{}_BINNAME_MAP", map_name_prefix),
            self.binary_name_map.len() as u32,
        );
        map
    }
}
