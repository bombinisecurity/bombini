//! Filemon config

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub file_open_config: HookConfig,
    pub path_truncate_config: HookConfig,
    pub path_unlink_config: HookConfig,
    /// Filter events by process information
    pub filter_mask: ProcessFilterMask,
    /// Use deny list for process filtering
    pub deny_list: bool,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct HookConfig {
    /// Export events to user mode
    pub expose_events: bool,
    /// Do not capture events at all
    pub disable: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
