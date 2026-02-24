//! Chmod filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::{
    config::rule::{FileNameMapKey, ImodeKey, PathChmodAttributes, PathMapKey, PathPrefixMapKey},
    event::file::Imode,
};

use crate::interpreter::CheckIn;

pub struct ImodeValue {
    pub rule_idx: u8,
    pub imode: Imode,
}

#[repr(C)]
pub struct ChmodFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub imode_map: &'a HashMap<ImodeKey, Imode>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub imode: &'a ImodeValue,
}

impl<'a> ChmodFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        imode_map: &'a HashMap<ImodeKey, Imode>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        imode: &'a ImodeValue,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            imode_map,
            name,
            path,
            prefix,
            imode,
        }
    }
}

impl CheckIn for ChmodFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == PathChmodAttributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == PathChmodAttributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == PathChmodAttributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == PathChmodAttributes::Imode as u8 => unsafe {
                let imode_key = ImodeKey {
                    rule_idx: self.imode.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(imode) = self.imode_map.get(&imode_key) else {
                    return Ok(false);
                };
                Ok(*imode & self.imode.imode != Imode::empty())
            },
            _ => Err(0),
        }
    }
}
