//! Transmutes NetworkEvent to serialized format

use bombini_common::event::network::{NetworkMsg, TcpConnectionV4, TcpConnectionV6};
use serde::Serialize;

use dns_lookup::getnameinfo;

use libc::NI_NAMEREQD;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::process::Process;
use super::{transmute_ktime, Transmute};

/// High-level event representation
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub struct NetworkEvent {
    /// Process Infro
    process: Process,
    /// Network event
    network_event: NetworkEventType,
    /// Event's date and time
    timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[repr(u8)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum NetworkEventType {
    TcpConnectionEstablish(TcpConnection),
    TcpConnectionClose(TcpConnection),
    TcpConnectionAccept(TcpConnection),
}

/// TCP IPv4 connection information
#[derive(Clone, Debug, Serialize)]
#[repr(C)]
pub struct TcpConnection {
    /// source IP address
    saddr: IpAddr,
    /// destination IP address,
    daddr: IpAddr,
    /// source port
    sport: u16,
    /// destination port
    dport: u16,
    /// socket cookie
    cookie: u64,
    /// FQDN dest for egress, source for ingress
    #[serde(skip_serializing_if = "String::is_empty")]
    fqdn: String,
}

impl NetworkEvent {
    /// Constructs High level event representation from low eBPF message
    pub fn new(event: NetworkMsg, ktime: u64) -> Self {
        match event {
            NetworkMsg::TcpConV4Establish(con) => {
                let mut con_event = transmute_connection_v4(&con);
                let sock: SocketAddr = (con_event.daddr, con_event.dport).into();
                if let Ok((fqdn, _)) = getnameinfo(&sock, NI_NAMEREQD) {
                    con_event.fqdn = fqdn;
                }
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionEstablish(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkMsg::TcpConV6Establish(con) => {
                let mut con_event = transmute_connection_v6(&con);
                let sock: SocketAddr = (con_event.daddr, con_event.dport).into();
                if let Ok((fqdn, _)) = getnameinfo(&sock, NI_NAMEREQD) {
                    con_event.fqdn = fqdn;
                }
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionEstablish(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkMsg::TcpConV4Close(con) => {
                let con_event = transmute_connection_v4(&con);
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionClose(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkMsg::TcpConV6Close(con) => {
                let con_event = transmute_connection_v6(&con);
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionClose(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkMsg::TcpConV4Accept(con) => {
                let mut con_event = transmute_connection_v4(&con);
                let sock: SocketAddr = (con_event.saddr, con_event.sport).into();
                if let Ok((fqdn, _)) = getnameinfo(&sock, NI_NAMEREQD) {
                    con_event.fqdn = fqdn;
                }
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionAccept(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
            NetworkMsg::TcpConV6Accept(con) => {
                let mut con_event = transmute_connection_v6(&con);
                let sock: SocketAddr = (con_event.saddr, con_event.sport).into();
                if let Ok((fqdn, _)) = getnameinfo(&sock, NI_NAMEREQD) {
                    con_event.fqdn = fqdn;
                }
                Self {
                    process: Process::new(con.process),
                    network_event: NetworkEventType::TcpConnectionAccept(con_event),
                    timestamp: transmute_ktime(ktime),
                }
            }
        }
    }
}

fn transmute_connection_v4(con: &TcpConnectionV4) -> TcpConnection {
    let s: [u8; 4] = Ipv4Addr::from_bits(con.saddr).octets();
    let d: [u8; 4] = Ipv4Addr::from_bits(con.daddr).octets();
    TcpConnection {
        saddr: IpAddr::V4(Ipv4Addr::new(s[3], s[2], s[1], s[0])),
        daddr: IpAddr::V4(Ipv4Addr::new(d[3], d[2], d[1], d[0])),
        sport: con.sport,
        dport: con.dport,
        cookie: con.cookie,
        fqdn: String::new(),
    }
}

fn transmute_connection_v6(con: &TcpConnectionV6) -> TcpConnection {
    TcpConnection {
        saddr: IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(con.saddr))),
        daddr: IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(con.daddr))),
        sport: con.sport,
        dport: con.dport,
        cookie: con.cookie,
        fqdn: String::new(),
    }
}

impl Transmute for NetworkEvent {}
