//! Filemon config

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub file_open_config: HookConfig,
    pub path_truncate_config: HookConfig,
    pub path_unlink_config: HookConfig,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct HookConfig {
    pub expose_events: bool,
    pub disable: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
