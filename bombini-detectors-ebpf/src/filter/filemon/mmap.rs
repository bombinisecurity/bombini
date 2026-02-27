//! Mmap filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::{
    config::rule::{
        FileNameMapKey, FlagsKey, MmapFileAttributes, PathMapKey, PathPrefixMapKey, ProtModeKey,
    },
    event::file::{ProtMode, SharingType},
};

use crate::interpreter::CheckIn;

pub struct ProtModeValue {
    pub rule_idx: u8,
    pub prot_mode: ProtMode,
}

pub struct MmapFlagsValue {
    pub rule_idx: u8,
    pub flags: SharingType,
}

#[repr(C)]
pub struct MmapFileFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub prot_mode_map: &'a HashMap<ProtModeKey, ProtMode>,
    pub flags_map: &'a HashMap<FlagsKey, SharingType>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub prot_mode: &'a ProtModeValue,
    pub flags: &'a MmapFlagsValue,
}

impl<'a> MmapFileFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        prot_mode_map: &'a HashMap<ProtModeKey, ProtMode>,
        flags_map: &'a HashMap<FlagsKey, SharingType>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        prot_mode: &'a ProtModeValue,
        flags: &'a MmapFlagsValue,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            prot_mode_map,
            flags_map,
            name,
            path,
            prefix,
            prot_mode,
            flags,
        }
    }
}

impl CheckIn for MmapFileFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == MmapFileAttributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == MmapFileAttributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == MmapFileAttributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == MmapFileAttributes::ProtMode as u8 => unsafe {
                let prot_key = ProtModeKey {
                    rule_idx: self.prot_mode.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(prot_mode) = self.prot_mode_map.get(&prot_key) else {
                    return Ok(false);
                };
                Ok(*prot_mode & self.prot_mode.prot_mode != ProtMode::empty())
            },
            id if id == MmapFileAttributes::Flags as u8 => unsafe {
                let flags_key = FlagsKey {
                    rule_idx: self.flags.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(flags) = self.flags_map.get(&flags_key) else {
                    return Ok(false);
                };
                Ok(*flags & self.flags.flags != SharingType::empty())
            },
            _ => Err(0),
        }
    }
}
