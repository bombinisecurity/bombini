//! Simple config ebpf map struct for filtering events by UID in simple detector

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SimpleUIDFilter {
    pub uid: u32,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for SimpleUIDFilter {}
}
