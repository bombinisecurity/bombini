//! Path filtering interface

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf,
    macros::map,
    maps::{
        hash_map::HashMap,
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
};
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};

use bombini_common::config::filemon::PathFilterMask;

#[map]
static FILTER_PATH_PREFIX_MAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

/// Holds references for filtering maps.
/// This set of maps represents a white list.
pub struct PathFilter<'a> {
    name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
    path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
    prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
}

impl<'a> PathFilter<'a> {
    /// Constracts PathFilter from maps references
    pub fn new(
        name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
        path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
        prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
    ) -> Self {
        PathFilter {
            name_map,
            path_map,
            prefix_map,
        }
    }

    /// Filter interface (NAME || PATH || PREFIX).
    pub fn filter(
        &self,
        mask: PathFilterMask,
        path: &[u8; MAX_FILE_PATH],
        name: &[u8; MAX_FILENAME_SIZE],
    ) -> bool {
        if mask.contains(PathFilterMask::NAME) && self.name_map.get_ptr(name).is_some() {
            return true;
        }
        if mask.contains(PathFilterMask::PATH) && self.path_map.get_ptr(path).is_some() {
            return true;
        }
        if mask.contains(PathFilterMask::PATH_PREFIX) {
            let Some(prefix) = FILTER_PATH_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            let _ = unsafe {
                aya_ebpf::memset(
                    prefix.data.as_mut_ptr(),
                    0,
                    core::mem::size_of_val(&prefix.data),
                );
                bpf_probe_read_kernel_buf(path as *const _, &mut prefix.data)
            };
            prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
            if self.prefix_map.get(prefix).is_some() {
                return true;
            }
        }
        false
    }
}
