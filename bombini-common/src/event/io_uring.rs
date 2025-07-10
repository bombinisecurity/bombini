//! IOUring event module

use crate::event::process::ProcInfo;

/// IOUring execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct IOUringMsg {
    pub process: ProcInfo,
    pub opcode: u8,
    pub flags: u64,
}
