//! Filemon config
use bitflags::bitflags;

use crate::event::file::FileEventNumber;

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    /// Filter events by process information
    pub filter_mask: ProcessFilterMask,
    /// Use deny list for process filtering
    pub deny_list: bool,
    /// Path filters for hooks
    pub path_mask: [PathFilterMask; FileEventNumber::TotalFileEvents as usize],
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

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum PathAttributes {
    Path = 0,
    PathPrefix,
    Name,
}
