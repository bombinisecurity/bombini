use crate::event::process::ProcessEventNumber;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ProcMonKernelConfig {
    pub ima_hash: bool,
    /// Option -> sandbox enabled, bool value deny_list
    pub sandbox_mode: [Option<bool>; ProcessEventNumber::TotalProcessEvents as usize],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for ProcMonKernelConfig {}
}
