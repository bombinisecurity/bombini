use aya_ebpf::maps::{LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{ConnectionAttributes, Ipv4MapKey, Ipv6MapKey};

use crate::interpreter::CheckIn;

#[repr(C)]
pub struct Ipv4Filter<'a> {
    pub src_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,
    pub dst_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,

    pub src_ip_addr: &'a Key<Ipv4MapKey>,
    pub dst_ip_addr: &'a Key<Ipv4MapKey>,
}

impl<'a> Ipv4Filter<'a> {
    pub fn new(
        src_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,
        dst_ip_addr_map: &'a LpmTrie<Ipv4MapKey, u8>,

        src_ip_addr: &'a Key<Ipv4MapKey>,
        dst_ip_addr: &'a Key<Ipv4MapKey>,
    ) -> Self {
        Self {
            src_ip_addr_map,
            dst_ip_addr_map,

            src_ip_addr,
            dst_ip_addr,
        }
    }
}

impl CheckIn for Ipv4Filter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == ConnectionAttributes::Ipv4Src as u8 => {
                let Some(mask_ip) = self.src_ip_addr_map.get(self.src_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == ConnectionAttributes::Ipv4Dst as u8 => {
                let Some(mask_ip) = self.dst_ip_addr_map.get(self.dst_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == ConnectionAttributes::Ipv6Src as u8
                || id == ConnectionAttributes::Ipv6Dst as u8 =>
            {
                // lookups for IPv6 are not possible while processing IPv4
                Ok(false)
            }
            _ => Err(0),
        }
    }
}

#[repr(C)]
pub struct Ipv6Filter<'a> {
    pub src_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,
    pub dst_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,

    pub src_ip_addr: &'a Key<Ipv6MapKey>,
    pub dst_ip_addr: &'a Key<Ipv6MapKey>,
}

impl<'a> Ipv6Filter<'a> {
    pub fn new(
        src_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,
        dst_ip_addr_map: &'a LpmTrie<Ipv6MapKey, u8>,

        src_ip_addr: &'a Key<Ipv6MapKey>,
        dst_ip_addr: &'a Key<Ipv6MapKey>,
    ) -> Self {
        Self {
            src_ip_addr_map,
            dst_ip_addr_map,

            src_ip_addr,
            dst_ip_addr,
        }
    }
}

impl CheckIn for Ipv6Filter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == ConnectionAttributes::Ipv6Src as u8 => {
                let Some(mask_ip) = self.src_ip_addr_map.get(self.src_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == ConnectionAttributes::Ipv6Dst as u8 => {
                let Some(mask_ip) = self.dst_ip_addr_map.get(self.dst_ip_addr) else {
                    return Ok(false);
                };
                Ok(*mask_ip & (1 << in_op_idx) != 0)
            }
            id if id == ConnectionAttributes::Ipv4Src as u8
                || id == ConnectionAttributes::Ipv4Dst as u8 =>
            {
                // lookups for IPv4 are not possible while processing IPv6
                Ok(false)
            }
            _ => Err(0),
        }
    }
}
