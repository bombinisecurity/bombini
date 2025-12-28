//! Event module provide generic event message for all detectors

pub mod file;
pub mod gtfobins;
pub mod io_uring;
pub mod network;
pub mod process;

/// Generic event for ring buffer
pub struct GenericEvent {
    pub ktime: u64,
    /// event enum discriminant for fast access
    pub msg_code: u8,
    pub event: Event,
}

/// Enumeration of all supported events
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum Event {
    // 0 - 31 reserved for common events
    /// Exec info (process, parent)
    ProcessExec((process::ProcInfo, process::ProcessKey)) = 0,
    /// Clone info (process, parent)
    ProcessClone((process::ProcInfo, process::ProcessKey)) = 1,
    /// Exit info (process, parent)
    ProcessExit((process::ProcessKey, process::ProcessKey)) = 2,
    Process(process::ProcessMsg) = 3,
    File(file::FileMsg) = 4,
    Network(network::NetworkMsg) = 5,
    /// IOUring submit request event type
    IOUring(io_uring::IOUringMsg) = 6,
    /// GTFOBins execution event type
    GTFOBins(gtfobins::GTFOBinsMsg) = 32,
}

// Event message codes

/// ProcExec message code
pub const MSG_PROCESS_EXEC: u8 = 0;
/// ProcClone message code
pub const MSG_PROCESS_CLONE: u8 = 1;
/// ProcExit message code
pub const MSG_PROCESS_EXIT: u8 = 2;
/// ProcEvent message code
pub const MSG_PROCESS: u8 = 3;
/// File message code
pub const MSG_FILE: u8 = 4;
/// Network message code
pub const MSG_NETWORK: u8 = 5;
/// IOUring submit request message code
pub const MSG_IOURING: u8 = 6;
/// GTFOBins execution message code
pub const MSG_GTFOBINS: u8 = 32;
