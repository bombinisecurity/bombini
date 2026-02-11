//! Network event module

use crate::event::process::ProcessKey;

/// TCP IPv4 connection information
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TcpConnectionV4 {
    /// source IP address
    pub saddr: u32,
    /// destination IP address,
    pub daddr: u32,
    /// source port
    pub sport: u16,
    /// destination port
    pub dport: u16,
    /// socket cookie
    pub cookie: u64,
}

/// TCP IPv6 connection information
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TcpConnectionV6 {
    /// source IP address
    pub saddr: [u8; 16],
    /// destination IP address,
    pub daddr: [u8; 16],
    /// source port
    pub sport: u16,
    /// destination port
    pub dport: u16,
    /// socket cookie
    pub cookie: u64,
}

/// Raw network event messages
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum NetworkEventVariant {
    /// Establishing TCP connection for IPv4
    TcpConV4Establish(TcpConnectionV4) = NetworkEventNumber::TcpConV4Establish as u8,
    /// Establishing TCP connection for IPv6
    TcpConV6Establish(TcpConnectionV6) = NetworkEventNumber::TcpConV6Establish as u8,
    /// Closing TCP connection for IPv4
    TcpConV4Close(TcpConnectionV4) = NetworkEventNumber::TcpConV4Close as u8,
    /// Closing TCP connection for IPv6
    TcpConV6Close(TcpConnectionV6) = NetworkEventNumber::TcpConV6Close as u8,
    /// Accepting TCP connection for IPv4
    TcpConV4Accept(TcpConnectionV4) = NetworkEventNumber::TcpConV4Accept as u8,
    /// Accepting TCP connection for IPv6
    TcpConV6Accept(TcpConnectionV6) = NetworkEventNumber::TcpConV6Accept as u8,
}

#[repr(C)]
pub enum NetworkEventNumber {
    TcpConV4Establish,
    TcpConV6Establish,
    TcpConV4Close,
    TcpConV6Close,
    TcpConV4Accept,
    TcpConV6Accept,

    TotalNetworkEvents,
}

/// Network event message with process info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct NetworkMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    pub event: NetworkEventVariant,
}
