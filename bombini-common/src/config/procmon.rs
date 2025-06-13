//! Procmon config
use bitflags::bitflags;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub expose_events: bool,
    pub filter_mask: ProcessFilterMask,
    pub deny_list: bool,
}

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq)]
    #[repr(C)]
    pub struct ProcessFilterMask: u64 {
        const BINARY_NAME = 0x0000000000000001;
        const BINARY_PATH = 0x0000000000000002;
        const BINARY_PATH_PREFIX = 0x0000000000000004;
        const UID = 0x0000000000000008;
        const EUID = 0x0000000000000010;
        const AUID = 0x0000000000000020;
        const E_CAPS = 0x0000000000000040;
    }
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
