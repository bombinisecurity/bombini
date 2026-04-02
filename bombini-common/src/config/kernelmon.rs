use crate::event::kernel::KernelEventNumber;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct KernelMonKernelConfig {
    /// Option -> sandbox enabled, bool value deny_list
    pub sandbox_mode: [Option<bool>; KernelEventNumber::TotalKernelEvents as usize],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for KernelMonKernelConfig {}
}
