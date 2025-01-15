//! GTFOBins event module

use crate::config::gtfobins::{MAX_ARGS_SIZE, MAX_FILENAME_SIZE};

/// GTFOBins execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct GTFOBinsMsg {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    /// if CAP_SET_UID is set in effective capabilities
    pub is_cap_set_uid: bool,
    /// if SETUID executable
    pub is_suid: bool,
    ///  executable file name + command line arguments without argv[0]
    pub command: [u8; MAX_FILENAME_SIZE + 1 + MAX_ARGS_SIZE],
}
