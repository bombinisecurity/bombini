//! Ioctl filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{
    CmdKey, FileIoctlAttributes, FileNameMapKey, PathMapKey, PathPrefixMapKey,
};

use crate::interpreter::CheckIn;

#[repr(C)]
pub struct FileIoctlFilter<'a> {
    pub name_map: &'a HashMap<FileNameMapKey, u8>,
    pub path_map: &'a HashMap<PathMapKey, u8>,
    pub prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
    pub cmd_map: &'a HashMap<CmdKey, u8>,

    pub name: &'a FileNameMapKey,
    pub path: &'a PathMapKey,
    pub prefix: &'a Key<PathPrefixMapKey>,
    pub cmd: &'a CmdKey,
}

impl<'a> FileIoctlFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_map: &'a HashMap<FileNameMapKey, u8>,
        path_map: &'a HashMap<PathMapKey, u8>,
        prefix_map: &'a LpmTrie<PathPrefixMapKey, u8>,
        cmd_map: &'a HashMap<CmdKey, u8>,

        name: &'a FileNameMapKey,
        path: &'a PathMapKey,
        prefix: &'a Key<PathPrefixMapKey>,
        cmd: &'a CmdKey,
    ) -> Self {
        Self {
            name_map,
            path_map,
            prefix_map,
            cmd_map,

            name,
            path,
            prefix,
            cmd,
        }
    }
}

impl CheckIn for FileIoctlFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == FileIoctlAttributes::Name as u8 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == FileIoctlAttributes::Path as u8 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            id if id == FileIoctlAttributes::PathPrefix as u8 => {
                let Some(mask_path) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            }
            id if id == FileIoctlAttributes::Cmd as u8 => unsafe {
                let Some(mask_cmd) = self.cmd_map.get(self.cmd) else {
                    return Ok(false);
                };
                Ok(*mask_cmd & (1 << in_op_idx) != 0)
            },
            _ => Err(0),
        }
    }
}
