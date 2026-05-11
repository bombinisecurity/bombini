//! LinPEAS event module

use crate::event::process::ProcessKey;

/// LinPEAS detection event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct LinPEASMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    /// detection layer: 0 - behavioral, 1 - signature
    pub kind: u8,
    /// observed enumeration categories bitmask
    pub mask: u8,
    /// number of observed unique categories
    pub category_count: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum LinPEASCategory {
    SuidSgid = 0,
    Capabilities = 1,
    SensitiveFiles = 2,
    SudoCheck = 3,
    ProcessEnum = 4,
    KernelInfo = 5,
    ContainerInfo = 6,
    NetworkInfo = 7,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum LinPEASAlertKind {
    Behavioral = 0,
    Signature = 1,
}
