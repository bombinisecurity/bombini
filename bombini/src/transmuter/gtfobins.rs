//! Transmutes GTFOBinsEvent to serialized format

use bombini_common::event::gtfobins::GTFOBinsMsg;

use serde::Serialize;

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct GTFOBinsEvent {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    /// if CAP_SET_UID is set in effective capabilities
    pub is_cap_set_uid: bool,
    /// if SETUID executable
    pub is_suid: bool,
    /// executable file name + command line arguments without argv[0]
    pub cmd: String,
}

impl GTFOBinsEvent {
    /// Constructs High level event representation from low eBPF
    pub fn new(mut event: GTFOBinsMsg) -> Self {
        event.command.iter_mut().for_each(|e| {
            if *e == 0x00 {
                *e = 0x20
            }
        });
        let cmd = String::from_utf8_lossy(&event.command)
            .trim_end()
            .to_string();
        Self {
            uid: event.uid,
            euid: event.euid,
            is_cap_set_uid: event.is_cap_set_uid,
            is_suid: event.is_suid,
            cmd,
        }
    }

    /// Get JSON reprsentation
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}
