//! Provide filtration interface for ProcInfo struct

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

use bombini_common::config::procmon::ProcessFilterMask;
use bombini_common::event::process::ProcInfo;

#[map]
static FILTER_BIN_PREFIX_MAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

/// Holds references for filtering maps.
/// This set of maps represents a white list.
pub struct ProcessFilter<'a> {
    uid_map: &'a HashMap<u32, u8>,
    euid_map: &'a HashMap<u32, u8>,
    auid_map: &'a HashMap<u32, u8>,
    binary_name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
    binary_path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
    binary_prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
}

impl<'a> ProcessFilter<'a> {
    /// Constracts ProcessFilter from maps references
    pub fn new(
        uid_map: &'a HashMap<u32, u8>,
        euid_map: &'a HashMap<u32, u8>,
        auid_map: &'a HashMap<u32, u8>,
        binary_name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
        binary_path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
        binary_prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
    ) -> Self {
        ProcessFilter {
            uid_map,
            euid_map,
            auid_map,
            binary_name_map,
            binary_path_map,
            binary_prefix_map,
        }
    }

    /// Check if proc satisfies the filter pattern:
    /// UID && EUID && AUID && (BIN_NAME || BIN_PATH || BIN_PREFIX).
    /// If deny_list is used return value must be inverted.
    pub fn filter(&self, mask: ProcessFilterMask, proc: &ProcInfo) -> bool {
        if mask.contains(ProcessFilterMask::UID) && self.uid_map.get_ptr(&proc.creds.uid).is_none()
        {
            return false;
        }
        if mask.contains(ProcessFilterMask::EUID)
            && self.euid_map.get_ptr(&proc.creds.euid).is_none()
        {
            return false;
        }
        if mask.contains(ProcessFilterMask::AUID) && self.auid_map.get_ptr(&proc.auid).is_none() {
            return false;
        }
        if mask
            .intersection(
                ProcessFilterMask::BINARY_NAME
                    | ProcessFilterMask::BINARY_PATH
                    | ProcessFilterMask::BINARY_PATH_PREFIX,
            )
            .is_empty()
        {
            return true;
        }
        if mask.contains(ProcessFilterMask::BINARY_NAME)
            && self.binary_name_map.get_ptr(&proc.filename).is_some()
        {
            return true;
        }
        if mask.contains(ProcessFilterMask::BINARY_PATH)
            && self.binary_path_map.get_ptr(&proc.binary_path).is_some()
        {
            return true;
        }
        if mask.contains(ProcessFilterMask::BINARY_PATH_PREFIX) {
            let Some(prefix) = FILTER_BIN_PREFIX_MAP.get_ptr_mut(0) else {
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
                bpf_probe_read_kernel_buf(&proc.binary_path as *const _, &mut prefix.data)
            };
            prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
            if self.binary_prefix_map.get(prefix).is_some() {
                return true;
            }
        }
        false
    }
}
