//! Credentials filters for bprm check

use aya_ebpf::maps::HashMap;
use bombini_common::{
    config::rule::{Attributes, CapKey, UIDKey},
    event::process::Capabilities,
};

use crate::{filter::procmon::cred::CapValue, interpreter::CheckIn};
use aya_ebpf::maps::{LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey};

#[repr(C)]
pub struct BprmCheckFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub euid_map: &'a HashMap<UIDKey, u8>,
    pub egid_map: &'a HashMap<UIDKey, u8>,
    pub ecap_map: &'a HashMap<CapKey, Capabilities>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub euid: &'a UIDKey,
    pub egid: &'a UIDKey,
    pub ecap: &'a CapValue,
}

impl<'a> BprmCheckFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        euid_map: &'a HashMap<UIDKey, u8>,
        egid_map: &'a HashMap<UIDKey, u8>,
        ecap_map: &'a HashMap<CapKey, Capabilities>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        euid: &'a UIDKey,
        egid: &'a UIDKey,
        ecap: &'a CapValue,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            euid_map,
            egid_map,
            ecap_map,
            name,
            path,
            prefix,
            euid,
            egid,
            ecap,
        }
    }
}

impl CheckIn for BprmCheckFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::EUID as u8 => unsafe {
                let Some(mask_path) = self.euid_map.get(self.euid) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::EGID as u8 => unsafe {
                let Some(mask_path) = self.egid_map.get(self.euid) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::ECAPS as u8 => unsafe {
                let ecap_key = CapKey {
                    rule_idx: self.ecap.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(caps) = self.ecap_map.get(ecap_key) else {
                    return Ok(false);
                };
                Ok(*caps & self.ecap.caps != Capabilities::empty())
            },
            _ => Err(-1),
        }
    }
}
