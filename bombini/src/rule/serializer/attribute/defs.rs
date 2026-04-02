use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::bail;
use aya::Ebpf;
use aya::maps::LpmTrie;
use aya::maps::hash_map::HashMap as EbpfHashMap;
use aya::maps::lpm_trie::Key;
use bombini_common::config::rule::{
    AccessModeKey, BpfIdKey, BpfMapTypeKey, BpfNameKey, BpfPrefixKey, BpfProgTypeKey, CapKey,
    CreationFlagsKey, FileNameMapKey, FlagsKey, ImodeKey, Ipv4MapKey, Ipv6MapKey, PathMapKey,
    PathPrefixMapKey, PortKey, ProtModeKey, UIDKey,
};
use bombini_common::constants::{
    MAX_BPFNAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE,
};
use bombini_common::event::file::{AccessMode, CreationFlags, Imode, ProtMode, SharingType};
use bombini_common::event::kernel::{BpfMapType, BpfProgType};
use bombini_common::event::process::Capabilities;

use crate::rule::{
    ast::Literal,
    serializer::attribute::{Attribute, util},
};

#[derive(Default, Debug, Clone)]
pub(crate) struct PathAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for PathAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut path_map: EbpfHashMap<_, PathMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{map_name_prefix}_PATH_MAP"))
                .unwrap(),
        )?;
        for (path, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_PATH_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]

pub(crate) struct NameAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for NameAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut name_map: EbpfHashMap<_, FileNameMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_NAME_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (name, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_NAME_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct PrefixAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for PrefixAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut prefix_map: LpmTrie<_, PathPrefixMapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_PREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.map.iter() {
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

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_PREFIX_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BinaryPathAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for BinaryPathAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut path_map: EbpfHashMap<_, PathMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{map_name_prefix}_BINPATH_MAP"))
                .unwrap(),
        )?;
        for (path, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_BINPATH_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]

pub(crate) struct BinaryNameAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for BinaryNameAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut name_map: EbpfHashMap<_, FileNameMapKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_BINNAME_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (name, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_BINNAME_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BinaryPrefixAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for BinaryPrefixAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut prefix_map: LpmTrie<_, PathPrefixMapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_BINPREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.map.iter() {
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

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_BINPREFIX_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct AccessModeAttribute {
    pub map: HashMap<AccessMode, u8>,
}

impl Attribute for AccessModeAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<AccessMode>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    AccessMode::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing access mode: {}", x))
                })
            })
            .collect();
        let values = values?;

        for mode in values {
            self.map
                .entry(mode)
                .and_modify(|value| *value |= 1 << in_idx)
                .or_insert(1 << in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut access_mode_map: EbpfHashMap<_, AccessModeKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ACCESS_MODE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (mode, value) in self.map.iter() {
            let key = AccessModeKey {
                rule_idx: rule_idx as u32,
                access_mode: *mode,
            };
            let _ = access_mode_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_ACCESS_MODE_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct CreationFlagsAttribute {
    pub map: HashMap<u8, CreationFlags>,
}

impl Attribute for CreationFlagsAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<CreationFlags>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    CreationFlags::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing creation flags: {}", x))
                })
            })
            .collect();
        let flags = values?
            .into_iter()
            .fold(CreationFlags::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("creation flags already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut creation_flags: EbpfHashMap<_, CreationFlagsKey, CreationFlags> =
            EbpfHashMap::try_from(
                ebpf.map_mut(&format!("{}_CREATION_FLAGS_MAP", map_name_prefix))
                    .unwrap(),
            )?;
        for (in_idx, value) in self.map.iter() {
            let key = CreationFlagsKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = creation_flags.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_CREATION_FLAGS_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct UIDAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for UIDAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_UID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_UID_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct EUIDAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for EUIDAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_EUID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_EUID_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct GIDAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for GIDAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_GID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_GID_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct EGIDAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for EGIDAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_EGID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_EGID_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct CmdAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for CmdAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, UIDKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_CMD_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = UIDKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_CMD_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct ImodeAttribute {
    pub map: HashMap<u8, Imode>,
}

impl Attribute for ImodeAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<Imode>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    Imode::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing Imode: {}", x))
                })
            })
            .collect();
        let flags = values?.into_iter().fold(Imode::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("Imode already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut mode_map: EbpfHashMap<_, ImodeKey, Imode> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_IMODE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.map.iter() {
            let key = ImodeKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = mode_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_IMODE_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct ProtModeAttribute {
    pub map: HashMap<u8, ProtMode>,
}

impl Attribute for ProtModeAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<ProtMode>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    ProtMode::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing prot mode: {}", x))
                })
            })
            .collect();
        let flags = values?.into_iter().fold(ProtMode::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("prot mode already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut prot_map: EbpfHashMap<_, ProtModeKey, ProtMode> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_PROT_MODE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.map.iter() {
            let key = ProtModeKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = prot_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_PROT_MODE_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct MmapFlagsAttribute {
    pub map: HashMap<u8, SharingType>,
}

impl Attribute for MmapFlagsAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<SharingType>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    SharingType::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing sharing type: {}", x))
                })
            })
            .collect();
        let flags = values?.into_iter().fold(SharingType::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("sharing type already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut flags_map: EbpfHashMap<_, FlagsKey, SharingType> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_FLAGS_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.map.iter() {
            let key = FlagsKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = flags_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_FLAGS_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct ECapsAttribute {
    pub map: HashMap<u8, Capabilities>,
}

impl Attribute for ECapsAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<Capabilities>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    Capabilities::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing capabilities: {}", x))
                })
            })
            .collect();
        let flags = values?
            .into_iter()
            .fold(Capabilities::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("capabilities already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ecap_map: EbpfHashMap<_, CapKey, Capabilities> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ECAP_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.map.iter() {
            let key = CapKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = ecap_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_ECAP_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct PCapsAttribute {
    pub map: HashMap<u8, Capabilities>,
}

impl Attribute for PCapsAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<Capabilities>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    Capabilities::from_str(&s)
                        .map_err(|x| anyhow::anyhow!("Error while parsing capabilities: {}", x))
                })
            })
            .collect();
        let flags = values?
            .into_iter()
            .fold(Capabilities::empty(), |a, b| a | b);

        if self.map.insert(in_idx, flags).is_some() {
            bail!("capabilities already set for index {}", in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ecap_map: EbpfHashMap<_, CapKey, Capabilities> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_PCAP_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (in_idx, value) in self.map.iter() {
            let key = CapKey {
                rule_idx,
                in_idx: *in_idx,
            };
            let _ = ecap_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_PCAP_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct IPv4SrcAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for IPv4SrcAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ipv4_src_map: LpmTrie<_, Ipv4MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_SRC_IPV4_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_SRC_IPV4_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]

pub(crate) struct IPv4DstAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for IPv4DstAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ipv4_dst_map: LpmTrie<_, Ipv4MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_DST_IPV4_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_DST_IPV4_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]

pub(crate) struct IPv6SrcAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for IPv6SrcAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ipv6_src_map: LpmTrie<_, Ipv6MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_SRC_IPV6_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_SRC_IPV6_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct IPv6DstAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for IPv6DstAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut ipv6_src_map: LpmTrie<_, Ipv6MapKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_DST_IPV6_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (cidr_str, value) in self.map.iter() {
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
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_DST_IPV6_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct PortSrcAttribute {
    pub map: HashMap<u16, u8>,
}

impl Attribute for PortSrcAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
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
        for port in values {
            self.map
                .entry(port)
                .and_modify(|value| *value |= 1 << in_idx)
                .or_insert(1 << in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut port_src_map: EbpfHashMap<_, PortKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_SRC_PORT_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (port, value) in self.map.iter() {
            let key = PortKey {
                rule_idx: rule_idx as u16,
                port: *port,
            };
            let _ = port_src_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_SRC_PORT_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct PortDstAttribute {
    pub map: HashMap<u16, u8>,
}

impl Attribute for PortDstAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
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
        for port in values {
            self.map
                .entry(port)
                .and_modify(|value| *value |= 1 << in_idx)
                .or_insert(1 << in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut port_src_map: EbpfHashMap<_, PortKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_DST_PORT_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (port, value) in self.map.iter() {
            let key = PortKey {
                rule_idx: rule_idx as u16,
                port: *port,
            };
            let _ = port_src_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_DST_PORT_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]

pub(crate) struct BpfNameAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for BpfNameAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut name_map: EbpfHashMap<_, BpfNameKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_NAME_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (name, value) in self.map.iter() {
            let mut key = BpfNameKey {
                rule_idx,
                name: [0u8; MAX_BPFNAME_SIZE],
            };
            let name_bytes = name.as_bytes();
            let len = name_bytes.len();
            if len < MAX_BPFNAME_SIZE {
                key.name[..len].clone_from_slice(name_bytes);
            } else {
                key.name.clone_from_slice(&name_bytes[..MAX_BPFNAME_SIZE]);
            }
            let _ = name_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_NAME_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BpfPrefixAttribute {
    pub map: HashMap<String, u8>,
}

impl Attribute for BpfPrefixAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_string_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut prefix_map: LpmTrie<_, BpfPrefixKey, u8> = LpmTrie::try_from(
            ebpf.map_mut(&format!("{}_PREFIX_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prefix, value) in self.map.iter() {
            let mut key = BpfPrefixKey {
                rule_idx,
                name: [0u8; MAX_BPFNAME_SIZE],
            };
            let prefix_bytes = prefix.as_bytes();
            let len = prefix_bytes.len();
            if len < MAX_BPFNAME_SIZE {
                key.name[..len].clone_from_slice(prefix_bytes);
            } else {
                key.name.clone_from_slice(&prefix_bytes[..MAX_BPFNAME_SIZE]);
            }
            let map_key = Key::new(((prefix.len() + 1) * 8) as u32, key);
            let _ = prefix_map.insert(&map_key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (
            format!("{map_name_prefix}_PREFIX_MAP"),
            self.map.len() as u32,
        )
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BpfIdAttribute {
    pub map: HashMap<u32, u8>,
}

impl Attribute for BpfIdAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        util::serialize_u32_attr(&mut self.map, values, in_idx)
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, BpfIdKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_ID_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (uid, value) in self.map.iter() {
            let key = BpfIdKey {
                rule_idx: rule_idx as u32,
                value: *uid,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_ID_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BpfMapTypeAttribute {
    pub map: HashMap<BpfMapType, u8>,
}

impl Attribute for BpfMapTypeAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<BpfMapType>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    serde_json::from_str(&format!("\"{s}\"")).map_err(|x| {
                        anyhow::anyhow!("Error while parsing bpf map type: {s}, {}", x)
                    })
                })
            })
            .collect();
        let values = values?;
        for key in values {
            self.map
                .entry(key)
                .and_modify(|value| *value |= 1 << in_idx)
                .or_insert(1 << in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, BpfMapTypeKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_TYPE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (map_type, value) in self.map.iter() {
            let key = BpfMapTypeKey {
                rule_idx: rule_idx as u32,
                map_type: *map_type,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_TYPE_MAP"), self.map.len() as u32)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct BpfProgTypeAttribute {
    pub map: HashMap<BpfProgType, u8>,
}

impl Attribute for BpfProgTypeAttribute {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error> {
        let values: Result<Vec<BpfProgType>, anyhow::Error> = values
            .iter()
            .map(|lit| match lit {
                Literal::String(s) => Ok(s.clone()),
                Literal::Uint(i) => Err(anyhow::anyhow!(
                    "expected String literal, found Uint: {}",
                    i
                )),
            })
            .map(|s| {
                s.and_then(|s| {
                    serde_json::from_str(&format!("\"{s}\"")).map_err(|x| {
                        anyhow::anyhow!("Error while parsing bpf map type: {s}, {}", x)
                    })
                })
            })
            .collect();
        let values = values?;
        for key in values {
            self.map
                .entry(key)
                .and_modify(|value| *value |= 1 << in_idx)
                .or_insert(1 << in_idx);
        }
        Ok(())
    }

    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        let mut uid_map: EbpfHashMap<_, BpfProgTypeKey, u8> = EbpfHashMap::try_from(
            ebpf.map_mut(&format!("{}_TYPE_MAP", map_name_prefix))
                .unwrap(),
        )?;
        for (prog_type, value) in self.map.iter() {
            let key = BpfProgTypeKey {
                rule_idx: rule_idx as u32,
                prog_type: *prog_type,
            };
            let _ = uid_map.insert(key, value, 0);
        }
        Ok(())
    }

    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32) {
        (format!("{map_name_prefix}_TYPE_MAP"), self.map.len() as u32)
    }
}
