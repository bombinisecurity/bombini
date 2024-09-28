//! GTFOBins event module

pub const MAX_FILENAME: usize = 64;

pub const MAX_ARGS_SIZE: usize = 256;

/// GTFOBins execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct GTFOBinsEvent {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    /// if CAP_SET_UID is set in effective capabilities
    pub is_cap_set_uid: bool,
    /// if SETUID executable
    pub is_suid: bool,
    /// executable name
    pub filename: [u8; MAX_FILENAME],
    /// command line arguments without argv[0]
    pub args: [u8; MAX_ARGS_SIZE],
}
