//! IOUringMon config

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub filter_mask: ProcessFilterMask,
    pub deny_list: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
