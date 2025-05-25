//! Network event module

use crate::event::process::ProcInfo;

/// TCP IPv4 connection information
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TcpConnectionV4 {
    pub process: ProcInfo,
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
    pub process: ProcInfo,
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
pub enum NetworkMsg {
    /// Establishing TCP connection for IPv4
    TcpConV4Establish(TcpConnectionV4) = 0,
    /// Establishing TCP connection for IPv6
    TcpConV6Establish(TcpConnectionV6) = 1,
    /// Closing TCP connection for IPv4
    TcpConV4Close(TcpConnectionV4) = 2,
    /// Closing TCP connection for IPv6
    TcpConV6Close(TcpConnectionV6) = 3,
    /// Accepting TCP connection for IPv4
    TcpConV4Accept(TcpConnectionV4) = 4,
    /// Accepting TCP connection for IPv6
    TcpConV6Accept(TcpConnectionV6) = 5,
}
