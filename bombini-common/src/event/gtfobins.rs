//! GTFOBins event module

use crate::event::process::ProcessKey;

/// GTFOBins execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct GTFOBinsMsg {
    pub process: ProcessKey,
}
