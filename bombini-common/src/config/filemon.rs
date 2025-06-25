//! Filemon config

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    /// Filter events by process information
    pub filter_mask: ProcessFilterMask,
    /// Use deny list for process filtering
    pub deny_list: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
