//! Socket parameter filters for netmon detector

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::{
    config::rule::{
        AddressFamilyKey, Attributes, Ipv4MapKey, Ipv6MapKey, PortKey, SocketFlagsKey,
        SocketTypeKey,
    },
    event::network::SocketFlags,
};

use crate::interpreter::CheckIn;

pub struct SocketFlagsValue {
    pub rule_idx: u8,
    pub flags: SocketFlags,
}

#[repr(C)]
pub struct SocketCreateFilter<'a> {
    pub family_map: &'a HashMap<AddressFamilyKey, u8>,
    pub stype_map: &'a HashMap<SocketTypeKey, u8>,
    pub sflags_map: &'a HashMap<SocketFlagsKey, SocketFlags>,

    pub family: &'a AddressFamilyKey,
    pub stype: &'a SocketTypeKey,
    pub sflags: &'a SocketFlagsValue,
}

impl<'a> SocketCreateFilter<'a> {
    pub fn new(
        family_map: &'a HashMap<AddressFamilyKey, u8>,
        stype_map: &'a HashMap<SocketTypeKey, u8>,
        sflags_map: &'a HashMap<SocketFlagsKey, SocketFlags>,

        family: &'a AddressFamilyKey,
        stype: &'a SocketTypeKey,
        sflags: &'a SocketFlagsValue,
    ) -> Self {
        Self {
            family_map,
            stype_map,
            sflags_map,
            family,
            stype,
            sflags,
        }
    }
}

impl CheckIn for SocketCreateFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::SockType as u8 => unsafe {
                let Some(mask_type) = self.stype_map.get(self.stype) else {
                    return Ok(false);
                };
                Ok(*mask_type & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::SockFlags as u8 => unsafe {
                let sflags_key = SocketFlagsKey {
                    rule_idx: self.sflags.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(sflags) = self.sflags_map.get(sflags_key) else {
                    return Ok(false);
                };
                Ok(*sflags & self.sflags.flags != SocketFlags::empty())
            },
            id if id == Attributes::SockFamily as u8 => unsafe {
                let Some(mask_family) = self.family_map.get(self.family) else {
                    return Ok(false);
                };
                Ok(*mask_family & (1 << in_op_idx) != 0)
            },
            _ => Err(-1),
        }
    }
}

#[repr(C)]
pub struct SocketConnectIPv4Filter<'a> {
    pub dst_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,
    pub dst_port_map: &'a HashMap<PortKey, u8>,

    pub dst_ip_addr: &'a Key<Ipv4MapKey>,
    pub dst_port: &'a PortKey,
}

impl<'a> SocketConnectIPv4Filter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dst_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,
        dst_port_map: &'a HashMap<PortKey, u8>,

        dst_ip_addr: &'a Key<Ipv4MapKey>,
        dst_port: &'a PortKey,
    ) -> Self {
        Self {
            dst_ip_addr_map,
            dst_port_map,

            dst_ip_addr,
            dst_port,
        }
    }
}

impl CheckIn for SocketConnectIPv4Filter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::Ipv4Dst as u8 => {
                let Some(mask_ip) = self.dst_ip_addr_map.get(self.dst_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::Ipv6Dst as u8 => {
                // lookups for IPv6 are not possible while processing IPv4
                Ok(false)
            }
            id if id == Attributes::PortDst as u8 => unsafe {
                let Some(mask_port) = self.dst_port_map.get(self.dst_port) else {
                    return Ok(false);
                };
                Ok(*mask_port & (1 << in_op_idx) != 0)
            },
            _ => Err(-1),
        }
    }
}

#[repr(C)]
pub struct SocketConnectIPv6Filter<'a> {
    pub dst_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,
    pub dst_port_map: &'a HashMap<PortKey, u8>,

    pub dst_ip_addr: &'a Key<Ipv6MapKey>,
    pub dst_port: &'a PortKey,
}

impl<'a> SocketConnectIPv6Filter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dst_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,
        dst_port_map: &'a HashMap<PortKey, u8>,

        dst_ip_addr: &'a Key<Ipv6MapKey>,
        dst_port: &'a PortKey,
    ) -> Self {
        Self {
            dst_ip_addr_map,
            dst_port_map,

            dst_ip_addr,
            dst_port,
        }
    }
}

impl CheckIn for SocketConnectIPv6Filter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::Ipv6Dst as u8 => {
                let Some(mask_ip) = self.dst_ip_addr_map.get(self.dst_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == Attributes::Ipv4Dst as u8 => {
                // lookups for IPv4 are not possible while processing IPv6
                Ok(false)
            }
            id if id == Attributes::PortDst as u8 => unsafe {
                let Some(mask_port) = self.dst_port_map.get(self.dst_port) else {
                    return Ok(false);
                };
                Ok(*mask_port & (1 << in_op_idx) != 0)
            },
            _ => Err(-1),
        }
    }
}
