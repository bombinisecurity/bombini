//! Networkmon config
use bitflags::bitflags;

use super::procmon::ProcessFilterMask;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Config {
    pub filter_mask: ProcessFilterMask,
    /// Process deny list
    pub deny_list: bool,
    pub ip_filter_mask: IpFilterMask,
}

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq)]
    #[repr(C)]
    pub struct IpFilterMask: u64 {
        const SOURCE_IP4_INGRESS_ALLOW = 0x0000000000000001;
        const DEST_IP4_INGRESS_ALLOW = 0x0000000000000002;
        const SOURCE_IP4_EGRESS_ALLOW = 0x0000000000000004;
        const DEST_IP4_EGRESS_ALLOW = 0x0000000000000008;
        const SOURCE_IP6_INGRESS_ALLOW = 0x0000000000000010;
        const DEST_IP6_INGRESS_ALLOW = 0x0000000000000020;
        const SOURCE_IP6_EGRESS_ALLOW = 0x0000000000000040;
        const DEST_IP6_EGRESS_ALLOW = 0x0000000000000080;
        const SOURCE_IP4_INGRESS_DENY = 0x0000000000000100;
        const DEST_IP4_INGRESS_DENY = 0x0000000000000200;
        const SOURCE_IP4_EGRESS_DENY = 0x0000000000000400;
        const DEST_IP4_EGRESS_DENY = 0x0000000000000800;
        const SOURCE_IP6_INGRESS_DENY = 0x0000000000001000;
        const DEST_IP6_INGRESS_DENY = 0x0000000000002000;
        const SOURCE_IP6_EGRESS_DENY = 0x0000000000004000;
        const DEST_IP6_EGRESS_DENY = 0x0000000000008000;
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ConnectionAttributes {
    Ipv4Src = 0,
    Ipv6Src,
    Ipv4Dst,
    Ipv6Dst,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Config {}
}
