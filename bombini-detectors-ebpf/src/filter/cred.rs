//! Cred filter interface

use aya_ebpf::maps::{array::Array, hash_map::HashMap};

use bombini_common::config::procmon::CredFilterMask;
use bombini_common::event::process::Capabilities;

pub struct UidFilter<'a> {
    euid_map: &'a HashMap<u32, u8>,
}

impl<'a> UidFilter<'a> {
    pub fn new(euid_map: &'a HashMap<u32, u8>) -> Self {
        UidFilter { euid_map }
    }

    pub fn filter(&self, mask: CredFilterMask, euid: u32) -> bool {
        if mask.contains(CredFilterMask::EUID) && self.euid_map.get_ptr(&euid).is_some() {
            return true;
        }
        false
    }
}

pub struct CapFilter<'a> {
    e_cap_map: &'a Array<u64>,
}

impl<'a> CapFilter<'a> {
    pub fn new(e_cap_map: &'a Array<u64>) -> Self {
        CapFilter { e_cap_map }
    }

    pub fn filter(&self, mask: CredFilterMask, e_cap: &Capabilities) -> bool {
        if mask.intersects(CredFilterMask::E_CAPS | CredFilterMask::E_CAPS_DENY_LIST) {
            for index in 0..64 {
                let Some(cap) = self.e_cap_map.get(index) else {
                    break;
                };
                if *cap == 0 {
                    break;
                }
                let cap = Capabilities::from_bits_truncate(*cap);
                if mask.contains(CredFilterMask::E_CAPS) && e_cap.contains(cap) {
                    return true;
                }
                if mask.contains(CredFilterMask::E_CAPS_DENY_LIST) && !e_cap.contains(cap) {
                    return true;
                }
            }
        }
        false
    }
}
