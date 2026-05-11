pub const LINPEASMON_FULLNAME_SIZE: usize = 256;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct LinPEASMonKernelConfig {
    pub behavioral_enabled: bool,
    pub signature_enabled: bool,
    pub threshold: u8,
    pub window_ns: u64,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct LinPEASMonState {
    pub mask: u8,
    pub last_seen_ns: [u64; 8],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for LinPEASMonKernelConfig {}
    unsafe impl aya::Pod for LinPEASMonState {}
}
