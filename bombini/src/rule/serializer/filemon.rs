use anyhow::{Ok, bail};
use aya::Ebpf;
use aya::maps::{
    hash_map::HashMap as EbpfHashMap,
    lpm_trie::{Key, LpmTrie},
};

use bombini_common::config::rule::{
    AccessModeKey, CreationFlagsKey, FileOpenAttributes, ImodeKey, PathChmodAttributes,
};
use bombini_common::event::file::{AccessMode, CreationFlags, Imode};
use bombini_common::{
    config::rule::{
        CmdKey, FileIoctlAttributes, FileNameMapKey, PathAttributes, PathChownAttributes,
        PathMapKey, PathPrefixMapKey, Predicate, RuleOp, UIDKey,
    },
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, MAX_RULE_OPERATIONS},
};

use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;

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
pub type PathUnlinkPredicate = PathPredicate;
pub type PathTruncatePredicate = PathPredicate;
pub type SbMountPredicate = PathPredicate;
pub type MmapFilePredicate = PathPredicate;

#[derive(Debug)]
pub struct FileOpenPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
    pub name_map: HashMap<String, u8>,

    pub access_mode_map: HashMap<AccessMode, u8>,
    pub creation_flags_map: HashMap<u8, CreationFlags>,
}

impl FileOpenPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            name_map: HashMap::new(),
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
            access_mode_map: HashMap::new(),
            creation_flags_map: HashMap::new(),
        }
    }
}

impl Default for FileOpenPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for FileOpenPredicate {
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
                Ok(PathChmodAttributes::Path as u8)
            }
            "name" => {
                for name in values {
                    self.name_map
                        .entry(name)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathChmodAttributes::Name as u8)
            }
            "path_prefix" => {
                for prefix in values {
                    self.path_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathChmodAttributes::PathPrefix as u8)
            }
            "access_mode" => {
                let values: Result<Vec<AccessMode>, anyhow::Error> = values
                    .iter()
                    .map(|s| {
                        AccessMode::from_str(s)
                            .map_err(|x| anyhow::anyhow!("Error while parsing access mode: {}", x))
                    })
                    .collect();
                let values = values?;

                for mode in values {
                    self.access_mode_map
                        .entry(mode)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(FileOpenAttributes::AccessMode as u8)
            }
            "creation_flags" => {
                let values: Result<Vec<CreationFlags>, anyhow::Error> = values
                    .iter()
                    .map(|s| {
                        CreationFlags::from_str(s)
                            .map_err(|x| anyhow::anyhow!("Error while parsing access mode: {}", x))
                    })
                    .collect();
                let flags = values?
                    .into_iter()
                    .fold(CreationFlags::empty(), |a, b| a | b);

                if self.creation_flags_map.insert(in_idx, flags).is_some() {
                    bail!("creation flags already set for index {}", in_idx);
                }
                Ok(FileOpenAttributes::CreationFlags as u8)
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

        let mut access_mode_map: EbpfHashMap<_, AccessModeKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ACCESS_MODE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (mode, value) in self.access_mode_map.iter() {
            let key = AccessModeKey {
                rule_idx: rule_idx as u32,
                access_mode: *mode,
            };
            let _ = access_mode_map.insert(key, value, 0);
        }

        let mut creation_flags: EbpfHashMap<_, CreationFlagsKey, CreationFlags> =
            EbpfHashMap::try_from(
                ebpf.map_mut(&format!("{}_CREATION_FLAGS_MAP", map_name_prefix))
                    .unwrap(),
            )?;
        for (in_idx, value) in self.creation_flags_map.iter() {
            let key = CreationFlagsKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = creation_flags.insert(key, value, 0);
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
        map.insert(
            format!("{}_ACCESS_MODE_MAP", map_name_prefix),
            self.access_mode_map.len() as u32,
        );
        map.insert(
            format!("{}_CREATION_FLAGS_MAP", map_name_prefix),
            self.creation_flags_map.len() as u32,
        );
        map
    }
}

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
#[derive(Debug)]
pub struct PathChownPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
    pub name_map: HashMap<String, u8>,
    pub uid_map: HashMap<u32, u8>,
    pub gid_map: HashMap<u32, u8>,
}

impl PathChownPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            name_map: HashMap::new(),
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
            uid_map: HashMap::new(),
            gid_map: HashMap::new(),
        }
    }
}

impl Default for PathChownPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for PathChownPredicate {
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
        if name == "uid" || name == "gid" {
            let values: Result<Vec<u32>, anyhow::Error> = values
                .iter()
                .map(|lit| match lit {
                    Literal::Uint(i) => Ok(*i as u32),
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
                    return Ok(PathChownAttributes::UID as u8);
                }
                "gid" => {
                    for gid in values {
                        self.gid_map
                            .entry(gid)
                            .and_modify(|value| *value |= 1 << in_idx)
                            .or_insert(1 << in_idx);
                    }
                    return Ok(PathChownAttributes::GID as u8);
                }
                _ => return Err(anyhow::anyhow!("invalid event attribute name: {}", name)),
            }
        }

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
        map.insert(
            format!("{}_UID_MAP", map_name_prefix),
            self.uid_map.len() as u32,
        );
        map.insert(
            format!("{}_GID_MAP", map_name_prefix),
            self.gid_map.len() as u32,
        );
        map
    }
}

#[derive(Debug)]
pub struct FileIoctlPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
    pub name_map: HashMap<String, u8>,
    pub cmd_map: HashMap<u32, u8>,
}

impl FileIoctlPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            name_map: HashMap::new(),
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
            cmd_map: HashMap::new(),
        }
    }
}

impl Default for FileIoctlPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for FileIoctlPredicate {
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
        if name == "cmd" {
            let values: Result<Vec<u32>, anyhow::Error> = values
                .iter()
                .map(|lit| match lit {
                    Literal::Uint(i) => Ok(*i as u32),
                    Literal::String(s) => Err(anyhow::anyhow!(
                        "expected Uint literal, found String: {}",
                        s
                    )),
                })
                .collect();
            let values = values?;
            for cmd in values {
                self.cmd_map
                    .entry(cmd)
                    .and_modify(|value| *value |= 1 << in_idx)
                    .or_insert(1 << in_idx);
            }
            return Ok(FileIoctlAttributes::Cmd as u8);
        }

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
                Ok(FileIoctlAttributes::Path as u8)
            }
            "name" => {
                for name in values {
                    self.name_map
                        .entry(name)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(FileIoctlAttributes::Name as u8)
            }
            "path_prefix" => {
                for prefix in values {
                    self.path_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(FileIoctlAttributes::PathPrefix as u8)
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
        let mut cmd_map: EbpfHashMap<_, CmdKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_CMD_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cmd, value) in self.cmd_map.iter() {
            let key = CmdKey {
                rule_idx: rule_idx as u32,
                uid: *cmd,
            };
            let _ = cmd_map.insert(key, value, 0);
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
        map.insert(
            format!("{}_CMD_MAP", map_name_prefix),
            self.cmd_map.len() as u32,
        );
        map
    }
}

#[derive(Debug)]
pub struct PathChmodPredicate {
    pub predicate: Predicate,
    pub path_map: HashMap<String, u8>,
    pub path_prefix_map: HashMap<String, u8>,
    pub name_map: HashMap<String, u8>,
    pub mode_map: HashMap<u8, Imode>,
}

impl PathChmodPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            name_map: HashMap::new(),
            path_map: HashMap::new(),
            path_prefix_map: HashMap::new(),
            mode_map: HashMap::new(),
        }
    }
}

impl Default for PathChmodPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for PathChmodPredicate {
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
        if name == "mode" {
            let values: Result<Vec<Imode>, anyhow::Error> = values
                .iter()
                .cloned()
                .map(|lit| match lit {
                    Literal::String(s) => Imode::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing mode: {}", x)),
                    Literal::Uint(i) => Err(anyhow::anyhow!(
                        "expected String literal, found Uint: {}",
                        i
                    )),
                })
                .collect();
            let mode = values?.into_iter().fold(Imode::empty(), |a, b| a | b);
            if self.mode_map.insert(in_idx, mode).is_some() {
                bail!("mode already set for index {}", in_idx);
            }
            return Ok(PathChmodAttributes::Imode as u8);
        }

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
                Ok(PathChmodAttributes::Path as u8)
            }
            "name" => {
                for name in values {
                    self.name_map
                        .entry(name)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathChmodAttributes::Name as u8)
            }
            "path_prefix" => {
                for prefix in values {
                    self.path_prefix_map
                        .entry(prefix)
                        .and_modify(|value| *value |= 1 << in_idx)
                        .or_insert(1 << in_idx);
                }
                Ok(PathChmodAttributes::PathPrefix as u8)
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

        let mut mode_map: EbpfHashMap<_, ImodeKey, Imode> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_IMODE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.mode_map.iter() {
            let key = ImodeKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = mode_map.insert(key, value, 0);
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
        map.insert(
            format!("{}_IMODE_MAP", map_name_prefix),
            self.mode_map.len() as u32,
        );
        map
    }
}
