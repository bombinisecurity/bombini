//! Event module provide generic event message for all detectors

/// Event messages
pub mod gtfobins;
pub mod simple;

/// Generic event for ring buffer
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(C, u8)]
pub enum Event {
    /// 0 - 31 reserved for common events
    /// Simple event type
    Simple(simple::SimpleMsg) = 32,
    /// GTFOBins execution event type
    GTFOBins(gtfobins::GTFOBinsMsg) = 33,
}

// Event message codes

/// Simple event message code
pub const MSG_SIMPLE: u8 = 32;

/// GTFOBins execution message code
pub const MSG_GTFOBINS: u8 = 33;
