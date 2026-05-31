//! Network event module

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

use bitflags::bitflags;

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

/// Socket creation information
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SocketCreate {
    /// socket family
    pub family: AddressFamily,
    /// socket type
    pub socket_type: SocketType,
    /// socket flags
    pub flags: SocketFlags,
    /// socket protocol number
    pub protocol: u32,
}

/// Socket connect information
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SocketConnect {
    /// socket family
    pub family: AddressFamily,
    /// socket type
    pub socket_type: SocketType,
    /// socket protocol number
    pub protocol: u32,
    /// Destination address
    pub daddr: IPAddress,
    /// Destination port
    pub dport: u16,
}

/// IP address representation
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub enum IPAddress {
    IPv4(u32),
    IPv6([u8; 16]),
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
    /// Creating socket
    SocketCreate(SocketCreate) = NetworkEventNumber::SocketCreate as u8,
    /// Socket connect
    SocketConnect(SocketConnect) = NetworkEventNumber::SocketConnect as u8,
}

/// Should be the same as in the kernel
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum AddressFamily {
    AF_UNSPEC = 0,
    AF_UNIX = 1, /* Same as AF_LOCAL */
    AF_INET = 2,
    AF_AX25 = 3,
    AF_IPX = 4,
    AF_APPLETALK = 5,
    AF_NETROM = 6,
    AF_BRIDGE = 7,
    AF_ATMPVC = 8,
    AF_X25 = 9,
    AF_INET6 = 10,
    AF_ROSE = 11,
    AF_DECnet = 12,
    AF_NETBEUI = 13,
    AF_SECURITY = 14,
    AF_KEY = 15,
    AF_NETLINK = 16, /* Same as AF_ROUTE */
    AF_PACKET = 17,
    AF_ASH = 18,
    AF_ECONET = 19,
    AF_ATMSVC = 20,
    AF_RDS = 21,
    AF_SNA = 22,
    AF_IRDA = 23,
    AF_PPPOX = 24,
    AF_WANPIPE = 25,
    AF_LLC = 26,
    AF_IB = 27,
    AF_MPLS = 28,
    AF_CAN = 29,
    AF_TIPC = 30,
    AF_BLUETOOTH = 31,
    AF_IUCV = 32,
    AF_RXRPC = 33,
    AF_ISDN = 34,
    AF_PHONET = 35,
    AF_IEEE802154 = 36,
    AF_CAIF = 37,
    AF_ALG = 38,
    AF_NFC = 39,
    AF_VSOCK = 40,
    AF_KCM = 41,
    AF_QIPCRTR = 42,
    AF_SMC = 43,
    AF_XDP = 44,
    AF_MCTP = 45,

    AF_MAX = 46,
}

/// Should be the same as in the kernel
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum SocketType {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct SocketFlags: u32 {
        const SOCK_CLOEXEC	= 0o2000000;
        const SOCK_NONBLOCK	= 0o4000;
    }
}

#[cfg(feature = "user")]
impl core::str::FromStr for SocketFlags {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags_str: &str) -> Result<Self, Self::Err> {
        bitflags::parser::from_str(flags_str)
    }
}

#[repr(C)]
pub enum NetworkEventNumber {
    TcpConV4Establish,
    TcpConV6Establish,
    TcpConV4Close,
    TcpConV6Close,
    TcpConV4Accept,
    TcpConV6Accept,
    SocketCreate,
    SocketConnect,

    TotalNetworkEvents,
}

/// Network event message with process info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct NetworkMsg {
    pub process: ProcessKey,
    pub parent: ProcessKey,
    pub event: NetworkEventVariant,
    /// true if event is blocked by corresponding LSM hook
    pub blocked: bool,
    pub rule_idx: Option<u8>,
}
