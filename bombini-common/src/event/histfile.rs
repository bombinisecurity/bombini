//! Histfile event module

use crate::event::process::ProcInfo;

pub const MAX_BASH_COMMAND_SIZE: usize = 128;

/// Histfile execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct HistFileMsg {
    /// bash proc info
    pub process: ProcInfo,
    /// bash read line
    pub command: [u8; MAX_BASH_COMMAND_SIZE],
}
