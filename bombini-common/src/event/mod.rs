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
    File(file::FileMsg) = 2,
    Network(network::NetworkMsg) = 3,
    /// IOUring submit request event type
    IOUring(io_uring::IOUringMsg) = 4,
    /// Proc setuid
    ProcSetUid(process::ProcSetUid) = 5,
    /// Proc capset
    ProcCapset(process::ProcCapset) = 6,
    /// Proc prctl
    ProcPrctl(process::ProcPrctl) = 7,
    /// create_user_ns
    ProcCreateUserNs(process::ProcCreateUserNs) = 8,
    /// ptrace_attach
    ProcPtraceAccessCheck(process::ProcPtraceAccessCheck) = 9,
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
/// File message code
pub const MSG_FILE: u8 = 2;
/// Network message code
pub const MSG_NETWORK: u8 = 3;
/// IOUring submit request message code
pub const MSG_IOURING: u8 = 4;
/// Process setuid message code
pub const MSG_SETUID: u8 = 5;
/// Process capset message code
pub const MSG_CAPSET: u8 = 6;
/// Process prctl message code
pub const MSG_PRCTL: u8 = 7;
/// Process create_user_ns message code
pub const MSG_CREATE_USER_NS: u8 = 8;
/// Process ptrace_attach message code
pub const MSG_PTRACE_ACCESS_CHECK: u8 = 9;
/// GTFOBins execution message code
pub const MSG_GTFOBINS: u8 = 32;
/// HISTFILESIZE/HISTSIZE modification message code
pub const MSG_HISTFILE: u8 = 33;
