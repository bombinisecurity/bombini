//! Path filters for file open hook

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LpmTrie, PerCpuArray, lpm_trie::Key},
};
use bombini_common::{
    config::{
        filemon::FileOpenAttributes,
        rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey},
    },
    constants::MAX_FILE_PREFIX,
};

use crate::interpreter::CheckIn;

#[map]
static FILE_OPEN_PATH_PREFIX_MAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
pub struct FileOpenFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
}

impl<'a> FileOpenFilter<'a> {
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            name,
            path,
            prefix,
        }
    }
}

impl CheckIn for FileOpenFilter<'_> {
    fn chech_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
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
            _ => Err(0),
        }
    }
}
