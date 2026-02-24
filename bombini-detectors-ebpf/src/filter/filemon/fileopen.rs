//! Chmod filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::{
    config::rule::{
        AccessModeKey, CreationFlagsKey, FileNameMapKey, FileOpenAttributes, PathMapKey,
        PathPrefixMapKey,
    },
    event::file::CreationFlags,
};

use crate::interpreter::CheckIn;

pub struct CreationFlagsValue {
    pub rule_idx: u8,
    pub creation_flags: CreationFlags,
}

#[repr(C)]
pub struct FileOpenFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub access_mode_map: &'a HashMap<AccessModeKey, u8>,
    pub creation_flags_map: &'a HashMap<CreationFlagsKey, CreationFlags>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub access_mode: &'a AccessModeKey,
    pub creation_flags: &'a CreationFlagsValue,
}

impl<'a> FileOpenFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        access_mode_map: &'a HashMap<AccessModeKey, u8>,
        creation_flags_map: &'a HashMap<CreationFlagsKey, CreationFlags>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        access_mode: &'a AccessModeKey,
        creation_flags: &'a CreationFlagsValue,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            access_mode_map,
            creation_flags_map,
            name,
            path,
            prefix,
            access_mode,
            creation_flags,
        }
    }
}

impl CheckIn for FileOpenFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == FileOpenAttributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == FileOpenAttributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == FileOpenAttributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == FileOpenAttributes::AccessMode as u8 => unsafe {
                let Some(mask_mode) = self.access_mode_map.get(self.access_mode) else {
                    return Ok(false);
                };
                Ok(*mask_mode & (1 << in_op_idx) != 0)
            },
            id if id == FileOpenAttributes::CreationFlags as u8 => unsafe {
                let cr_value = CreationFlagsKey {
                    rule_idx: self.creation_flags.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(flags) = self.creation_flags_map.get(&cr_value) else {
                    return Ok(false);
                };
                Ok(*flags & self.creation_flags.creation_flags != CreationFlags::empty())
            },
            _ => Err(0),
        }
    }
}
