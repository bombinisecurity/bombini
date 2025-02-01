//! Event module provide generic event message for all detectors

pub mod process;

/// Event messages
pub mod gtfobins;
pub mod histfile;

/// Generic event for ring buffer
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(C, u8)]
pub enum Event {
    /// 0 - 31 reserved for common events
    /// GTFOBins execution event type
    GTFOBins(gtfobins::GTFOBinsMsg) = 32,
    /// Histfile modification event type
    HistFile(histfile::HistFileMsg) = 33,
}

// Event message codes

/// GTFOBins execution message code
pub const MSG_GTFOBINS: u8 = 32;
/// HISTFILESIZE/HISTSIZE modification message code
pub const MSG_HISTFILE: u8 = 33;
