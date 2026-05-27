//! SysEnum event module

use crate::config::sysenummon::{ChainItem, SYSENUMMON_CHAIN_MAX};
use crate::event::process::ProcessKey;

/// System enumeration alert
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SysEnumMonMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    /// number of valid items in chain
    pub chain_len: u8,
    /// sequence of executed binaries / opened files that led to the alert
    pub chain: [ChainItem; SYSENUMMON_CHAIN_MAX],
}
