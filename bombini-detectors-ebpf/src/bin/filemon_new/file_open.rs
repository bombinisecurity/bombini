//! Path filters for file open hook

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf,
    macros::map,
    maps::{HashMap, LpmTrie, PerCpuArray, lpm_trie::Key},
};
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};

use crate::interpreter::CheckIn;

#[map]
static FILE_OPEN_PATH_PREFIX_MAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

pub struct FileOpenFilter<'a> {
    pub name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u64>,
    pub path_map: &'a HashMap<[u8; MAX_FILE_PATH], u64>,
    pub prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u64>,

    pub name: &'a [u8; MAX_FILENAME_SIZE],
    pub path: &'a [u8; MAX_FILE_PATH],
}

impl CheckIn for FileOpenFilter<'_> {
    fn chech_in_op(&self, attribute_map_id: u8, in_op_idx: u64) -> Result<bool, i32> {
        match attribute_map_id {
            0 => unsafe {
                let Some(mask_name) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(mask_name & (1 << in_op_idx) != 0)
            },
            1 => unsafe {
                let Some(mask_path) = self.path_map.get(self.path) else {
                    return Ok(false);
                };
                Ok(mask_path & (1 << in_op_idx) != 0)
            },
            2 => {
                let Some(prefix) = FILE_OPEN_PATH_PREFIX_MAP.get_ptr_mut(0) else {
                    return Err(0);
                };
                let prefix = unsafe { prefix.as_mut() };
                let Some(prefix) = prefix else {
                    return Err(0);
                };
                let _ = unsafe {
                    aya_ebpf::memset(
                        prefix.data.as_mut_ptr(),
                        0,
                        core::mem::size_of_val(&prefix.data),
                    );
                    bpf_probe_read_kernel_buf(self.path as *const _, &mut prefix.data)
                };
                prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
                let Some(mask_path) = self.prefix_map.get(prefix) else {
                    return Ok(false);
                };
                Ok(mask_path & (1 << in_op_idx) != 0)
            }
            _ => Err(0),
        }
    }
}
