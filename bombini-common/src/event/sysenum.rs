//! SysEnum event module

use crate::constants::{MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use crate::event::process::ProcessKey;

// Must be 2^n - 1 (used as a bit mask).
pub const SYSENUMMON_CHAIN_MAX: usize = 7;

#[repr(C)]
pub enum ChainItemNumber {
    Exec,
    FileOpen,
}

/// Single observation in a correlation chain: exec'd binary name or opened file path.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ChainItemType {
    Exec([u8; MAX_FILENAME_SIZE]) = ChainItemNumber::Exec as u8,
    FileOpen([u8; MAX_FILE_PREFIX]) = ChainItemNumber::FileOpen as u8,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ChainItem {
    pub timestamp_ns: u64,
    pub entry: ChainItemType,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SysEnumMsg {
    pub chain_len: u8,
    pub head: u8,
    pub process: ProcessKey,
    /// Watch-list ids already in the chain; used only for in-kernel dedup.
    pub watch_ids: [u8; SYSENUMMON_CHAIN_MAX + 1],
    pub chain: [ChainItem; SYSENUMMON_CHAIN_MAX + 1],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for ChainItemType {}
    unsafe impl aya::Pod for ChainItem {}
    unsafe impl aya::Pod for SysEnumMsg {}
}
