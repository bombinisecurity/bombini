#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SysEnumMonKernelConfig {
    /// Number of unique observations in a window required to emit an event.
    pub chain_size: u8,
    /// Sliding window length in nanoseconds.
    pub window_ns: u64,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for SysEnumMonKernelConfig {}
}
