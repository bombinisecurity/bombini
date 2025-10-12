//! Filemon config
use bitflags::bitflags;

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    /// Filter events by process information
    pub filter_mask: ProcessFilterMask,
    /// Use deny list for process filtering
    pub deny_list: bool,
    /// Path filters for hooks
    /// 0 - file_open
    /// 1 - path_truncate
    /// 2 - path_unlink
    /// 3 - path_chmod
    /// 4 - path_chown
    /// 5 - sb_mount
    /// 6 - mmap_file
    /// 7 - file_ioctl
    pub path_mask: [PathFilterMask; 8],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq)]
    #[repr(C)]
    pub struct PathFilterMask: u64 {
        const NAME = 0x0000000000000001;
        const PATH = 0x0000000000000002;
        const PATH_PREFIX = 0x0000000000000004;
    }
}
