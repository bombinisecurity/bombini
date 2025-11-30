//! Transmutes IOUringEvent to serialized format

use anyhow::anyhow;
use async_trait::async_trait;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bombini_common::event::{
    Event,
    io_uring::{IOUringMsg, IOUringOp},
};

use serde::Serialize;

use crate::transmuter::str_from_bytes;

use super::file::{AccessMode, CreationFlags};
use super::process::Process;
use super::{Transmuter, transmute_ktime};

/// io_uring events
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IOUringEvent {
    /// Process information
    process: Process,
    /// io_uring_ops
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    opcode: IOUringOp,
    /// extra info for operation
    #[serde(skip_serializing_if = "no_iouring_extra_info")]
    op_info: IOUringOpInfo,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[repr(u8)]
#[allow(dead_code)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum IOUringOpInfo {
    FileOpen {
        path: String,
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        access_flags: AccessMode,
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        creation_flags: CreationFlags,
    },
    Statx {
        path: String,
    },
    Unlinkat {
        path: String,
    },
    ConnectAccept {
        #[cfg_attr(feature = "schema", schemars(with = "String"))]
        addr: IpAddr,
        port: u16,
    },
    NoInfo,
}

fn no_iouring_extra_info(info: &IOUringOpInfo) -> bool {
    matches!(info, IOUringOpInfo::NoInfo)
}

impl IOUringEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: &IOUringMsg, ktime: u64) -> Self {
        let op_info = match event.opcode {
            IOUringOp::IORING_OP_OPENAT | IOUringOp::IORING_OP_OPENAT2 => IOUringOpInfo::FileOpen {
                path: str_from_bytes(&event.path),
                access_flags: AccessMode::from_bits_truncate(1 << (event.flags & 3)),
                creation_flags: CreationFlags::from_bits_truncate(event.flags as u32),
            },
            IOUringOp::IORING_OP_STATX => IOUringOpInfo::Statx {
                path: str_from_bytes(&event.path),
            },
            IOUringOp::IORING_OP_UNLINKAT => IOUringOpInfo::Unlinkat {
                path: str_from_bytes(&event.path),
            },
            IOUringOp::IORING_OP_CONNECT | IOUringOp::IORING_OP_ACCEPT => {
                match event.sockaddr[0] /* sa_family */ {
                    2 /* AF_INET */ => {
                        let addr = IpAddr::V4(Ipv4Addr::new(event.sockaddr[4], event.sockaddr[5], event.sockaddr[6], event.sockaddr[7]));
                        IOUringOpInfo::ConnectAccept { addr, port: u16::from_be_bytes(event.sockaddr[2..4].try_into().unwrap()) }
                    },
                    10 /* AF_INET6 */ => {
                        let addr = IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(event.sockaddr[4..21].try_into().unwrap())));
                        IOUringOpInfo::ConnectAccept { addr, port: u16::from_be_bytes(event.sockaddr[2..4].try_into().unwrap()) }
                    },
                    _ => IOUringOpInfo::NoInfo,
                }
            }
            _ => IOUringOpInfo::NoInfo,
        };
        Self {
            process: Process::new(&event.process),
            opcode: event.opcode.clone(),
            op_info,
            timestamp: transmute_ktime(ktime),
        }
    }
}

pub struct IOUringEventTransmuter;

#[async_trait]
impl Transmuter for IOUringEventTransmuter {
    async fn transmute(&self, event: &Event, ktime: u64) -> Result<Vec<u8>, anyhow::Error> {
        if let Event::IOUring(event) = event {
            let high_level_event = IOUringEvent::new(event, ktime);
            Ok(serde_json::to_vec(&high_level_event)?)
        } else {
            Err(anyhow!("Unexpected event variant"))
        }
    }
}

#[cfg(all(test, feature = "schema"))]
mod schema {
    use super::IOUringEvent;
    use std::{env, fs::OpenOptions, io::Write, path::PathBuf};

    #[test]
    fn generate_gtfobins_event_schema() {
        let event_ref =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&event_ref)
            .unwrap();
        let _ = writeln!(file, "## IOUringMon\n\n```json");
        let schema = schemars::schema_for!(IOUringEvent);
        let _ = writeln!(file, "{}", serde_json::to_string_pretty(&schema).unwrap());
        let _ = writeln!(file, "```\n");
    }
}
