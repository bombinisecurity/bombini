use aya::Ebpf;
use aya::maps::{
    hash_map::HashMap as EbpfHashMap,
    lpm_trie::{Key, LpmTrie},
};

use bombini_common::{
    config::{
        filemon::PathAttributes,
        rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey, Predicate, RuleOp},
    },
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, MAX_RULE_OPERATIONS},
};

use std::collections::HashMap;
use std::fmt::Debug;

use super::PredicateSerializer;
use crate::rule::ast::Literal;

#[derive(Debug)]
pub struct PathPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
    pub name_map: HashMap<String, u8>,
}

impl PathPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            name_map: HashMap::new(),
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
        }
    }
}

impl Default for PathPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for PathPredicate {
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
            "path" => {
                for path in values {
                    self.path_map
                        .entry(path)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathAttributes::Path as u8)
            }
            "name" => {
                for name in values {
                    self.name_map
                        .entry(name)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathAttributes::Name as u8)
            }
            "path_prefix" => {
                for prefix in values {
                    self.path_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathAttributes::PathPrefix as u8)
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
        let mut path_map: EbpfHashMap<_, PathMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_PATH_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (path, value) in self.path_map.iter() {
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
            let _ = path_map.insert(key, value, 0);
        }

        let mut name_map: EbpfHashMap<_, FileNameMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_NAME_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (name, value) in self.name_map.iter() {
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
            let _ = name_map.insert(key, value, 0);
        }

        let mut prefix_map: LpmTrie<_, PathPrefixMapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_PREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.path_prefix_map.iter() {
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
            let _ = prefix_map.insert(&map_key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_PREFIX_MAP", map_name_prefix),
            self.path_prefix_map.len() as u32,
        );
        map.insert(
            format!("{}_PATH_MAP", map_name_prefix),
            self.path_map.len() as u32,
        );
        map.insert(
            format!("{}_NAME_MAP", map_name_prefix),
            self.name_map.len() as u32,
        );
        map
    }
}

// For now we have the same set of attributes for all hooks in FileMon. Let's use type aliasing.
pub type FileOpenPredicate = PathPredicate;
pub type PathUnlinkPredicate = PathPredicate;
pub type PathTruncatePredicate = PathPredicate;
pub type PathChmodPredicate = PathPredicate;
pub type PathChownPredicate = PathPredicate;
pub type SbMountPredicate = PathPredicate;
pub type MmapFilePredicate = PathPredicate;
pub type FileIoctlPredicate = PathPredicate;

#[derive(Debug)]
pub struct PathSymlinkPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
}

impl PathSymlinkPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
        }
    }
}

impl Default for PathSymlinkPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for PathSymlinkPredicate {
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
            "path" => {
                for path in values {
                    self.path_map
                        .entry(path)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathAttributes::Path as u8)
            }
            "path_prefix" => {
                for prefix in values {
                    self.path_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathAttributes::PathPrefix as u8)
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
        let mut path_map: EbpfHashMap<_, PathMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_PATH_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (path, value) in self.path_map.iter() {
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
            let _ = path_map.insert(key, value, 0);
        }

        let mut prefix_map: LpmTrie<_, PathPrefixMapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_PREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.path_prefix_map.iter() {
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
            let _ = prefix_map.insert(&map_key, value, 0);
        }
        Ok(())
    }

    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_PREFIX_MAP", map_name_prefix),
            self.path_prefix_map.len() as u32,
        );
        map.insert(
            format!("{}_PATH_MAP", map_name_prefix),
            self.path_map.len() as u32,
        );
        map
    }
}
