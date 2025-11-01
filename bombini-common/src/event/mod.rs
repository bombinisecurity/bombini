//! Event module provide generic event message for all detectors

pub mod file;
pub mod network;
pub mod process;

/// Event messages
pub mod gtfobins;
pub mod histfile;
pub mod io_uring;

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
    /// 0 - 31 reserved for common events
    ProcExec(process::ProcInfo) = 0,
    ProcExit(process::ProcInfo) = 1,
    Process(process::ProcessMsg) = 2,
    File(file::FileMsg) = 3,
    Network(network::NetworkMsg) = 4,
    /// IOUring submit request event type
    IOUring(io_uring::IOUringMsg) = 5,
    /// GTFOBins execution event type
    GTFOBins(gtfobins::GTFOBinsMsg) = 32,
    /// Histfile modification event type
    HistFile(histfile::HistFileMsg) = 33,
}

// Event message codes

/// ProcExec message code
pub const MSG_PROCEXEC: u8 = 0;
/// ProcExit message code
pub const MSG_PROCEXIT: u8 = 1;
/// ProcEvent message code
pub const MSG_PROCESS: u8 = 2;
/// File message code
pub const MSG_FILE: u8 = 3;
/// Network message code
pub const MSG_NETWORK: u8 = 4;
/// IOUring submit request message code
pub const MSG_IOURING: u8 = 5;
/// GTFOBins execution message code
pub const MSG_GTFOBINS: u8 = 32;
/// HISTFILESIZE/HISTSIZE modification message code
pub const MSG_HISTFILE: u8 = 33;
