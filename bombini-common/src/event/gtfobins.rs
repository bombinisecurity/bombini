//! GTFOBins event module

use crate::event::process::ProcInfo;

/// GTFOBins execution event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct GTFOBinsMsg {
    pub process: ProcInfo,
}
