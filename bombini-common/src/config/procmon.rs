#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ProcMonKernelConfig {
    pub ima_hash: bool,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for ProcMonKernelConfig {}
}
