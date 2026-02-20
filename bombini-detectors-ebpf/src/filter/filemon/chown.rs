//! Chown filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{
    FileNameMapKey, PathChownAttributes, PathMapKey, PathPrefixMapKey, UIDKey,
};

use crate::interpreter::CheckIn;

#[repr(C)]
pub struct ChownFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub uid_map: &'a HashMap<UIDKey, u8>,
    pub gid_map: &'a HashMap<UIDKey, u8>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub uid: &'a UIDKey,
    pub gid: &'a UIDKey,
}

impl<'a> ChownFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        uid_map: &'a HashMap<UIDKey, u8>,
        gid_map: &'a HashMap<UIDKey, u8>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        uid: &'a UIDKey,
        gid: &'a UIDKey,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            uid_map,
            gid_map,

            name,
            path,
            prefix,
            uid,
            gid,
        }
    }
}

impl CheckIn for ChownFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == PathChownAttributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == PathChownAttributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == PathChownAttributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == PathChownAttributes::UID as u8 => unsafe {
                let Some(mask_uid) = self.uid_map.get(self.uid) else {
                    return Ok(false);
                };
                Ok(*mask_uid & (1 << in_op_idx) != 0)
            },
            id if id == PathChownAttributes::GID as u8 => unsafe {
                let Some(mask_gid) = self.gid_map.get(self.gid) else {
                    return Ok(false);
                };
                Ok(*mask_gid & (1 << in_op_idx) != 0)
            },
            _ => Err(0),
        }
    }
}
