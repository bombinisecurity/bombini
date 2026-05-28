use crate::event::network::NetworkEventNumber;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct NetMonKernelConfig {
    /// Option -> sandbox enabled, bool value deny_list
    pub sandbox_mode: [Option<bool>; NetworkEventNumber::TotalNetworkEvents as usize],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for NetMonKernelConfig {}
}
