use crate::event::file::FileEventNumber;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct FileMonKernelConfig {
    /// Option -> sandbox enabled, bool value deny_list
    pub sandbox_mode: [Option<bool>; FileEventNumber::TotalFileEvents as usize],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for FileMonKernelConfig {}
}
