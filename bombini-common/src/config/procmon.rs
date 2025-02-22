//! Procmon config

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub expose_events: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
