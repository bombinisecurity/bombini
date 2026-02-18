//! Credentials filters for procmon detector

use aya_ebpf::maps::HashMap;
use bombini_common::{
    config::rule::{CapKey, CredAttributes, UIDKey},
    event::process::Capabilities,
};

use crate::interpreter::CheckIn;

pub struct CapValue {
    pub rule_idx: u8,
    pub caps: Capabilities,
}

#[repr(C)]
pub struct UidFilter<'a> {
    pub id_map: &'a HashMap<UIDKey, u8>,
    pub eid_map: &'a HashMap<UIDKey, u8>,

    pub id: &'a UIDKey,
    pub eid: &'a UIDKey,
}

impl<'a> UidFilter<'a> {
    pub fn new(
        id_map: &'a HashMap<UIDKey, u8>,
        eid_map: &'a HashMap<UIDKey, u8>,

        id: &'a UIDKey,
        eid: &'a UIDKey,
    ) -> Self {
        Self {
            id_map,
            eid_map,
            id,
            eid,
        }
    }
}

impl CheckIn for UidFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == CredAttributes::UID as u8 || id == CredAttributes::GID as u8 => unsafe {
                let Some(mask_name) = self.id_map.get(self.id) else {
                    return Ok(false);
                };
                Ok(*mask_name & (1 << in_op_idx) != 0)
            },
            id if id == CredAttributes::EUID as u8 || id == CredAttributes::EGID as u8 => unsafe {
                let Some(mask_path) = self.eid_map.get(self.eid) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            _ => Err(0),
        }
    }
}

#[repr(C)]
pub struct CapFilter<'a> {
    pub ecap_map: &'a HashMap<CapKey, Capabilities>,
    pub pcap_map: &'a HashMap<CapKey, Capabilities>,

    pub ecap: &'a CapValue,
    pub pcap: &'a CapValue,
}

impl<'a> CapFilter<'a> {
    pub fn new(
        ecap_map: &'a HashMap<CapKey, Capabilities>,
        pcap_map: &'a HashMap<CapKey, Capabilities>,

        ecap_rule_idx: &'a CapValue,
        pcap_rule_idx: &'a CapValue,
    ) -> Self {
        Self {
            ecap_map,
            pcap_map,
            ecap: ecap_rule_idx,
            pcap: pcap_rule_idx,
        }
    }
}

impl CheckIn for CapFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == CredAttributes::ECAPS as u8 => unsafe {
                let ecap_key = CapKey {
                    rule_idx: self.ecap.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(caps) = self.ecap_map.get(&ecap_key) else {
                    return Ok(false);
                };
                Ok(*caps & self.ecap.caps != Capabilities::empty())
            },
            id if id == CredAttributes::PCAPS as u8 => unsafe {
                let pcap_key = CapKey {
                    rule_idx: self.pcap.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(caps) = self.pcap_map.get(&pcap_key) else {
                    return Ok(false);
                };
                Ok(*caps & self.pcap.caps != Capabilities::empty())
            },
            _ => Err(0),
        }
    }
}

#[repr(C)]
pub struct CredFilter<'a> {
    pub ecap_map: &'a HashMap<CapKey, Capabilities>,
    pub euid_map: &'a HashMap<UIDKey, u8>,

    pub ecap: &'a CapValue,
    pub euid: &'a UIDKey,
}

impl<'a> CredFilter<'a> {
    pub fn new(
        ecap_map: &'a HashMap<CapKey, Capabilities>,
        euid_map: &'a HashMap<UIDKey, u8>,

        ecap: &'a CapValue,
        euid: &'a UIDKey,
    ) -> Self {
        Self {
            ecap_map,
            euid_map,
            ecap,
            euid,
        }
    }
}

impl CheckIn for CredFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == CredAttributes::ECAPS as u8 => unsafe {
                let ecap_key = CapKey {
                    rule_idx: self.ecap.rule_idx,
                    in_idx: in_op_idx,
                };
                let Some(caps) = self.ecap_map.get(&ecap_key) else {
                    return Ok(false);
                };
                Ok(*caps & self.ecap.caps != Capabilities::empty())
            },
            id if id == CredAttributes::EUID as u8 => unsafe {
                let Some(mask_path) = self.euid_map.get(self.euid) else {
                    return Ok(false);
                };
                Ok(*mask_path & (1 << in_op_idx) != 0)
            },
            _ => Err(0),
        }
    }
}
