//! Bpf map filter

use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{
    Attributes, BpfIdKey, BpfNameKey, BpfPrefixKey, BpfProgTypeKey,
};

use crate::interpreter::CheckIn;

#[repr(C)]
pub struct BpfProgFilter<'a> {
    pub id_map: &'a HashMap<BpfIdKey, u8>,
    pub type_map: &'a HashMap<BpfProgTypeKey, u8>,
    pub name_map: &'a HashMap<BpfNameKey, u8>,
    pub prefix_map: &'a LpmTrie<BpfPrefixKey, u8>,

    pub id: &'a BpfIdKey,
    pub map_type: &'a BpfProgTypeKey,
    pub name: &'a BpfNameKey,
    pub prefix: &'a Key<BpfPrefixKey>,
}

impl<'a> BpfProgFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id_map: &'a HashMap<BpfIdKey, u8>,
        type_map: &'a HashMap<BpfProgTypeKey, u8>,
        name_map: &'a HashMap<BpfNameKey, u8>,
        prefix_map: &'a LpmTrie<BpfPrefixKey, u8>,

        id: &'a BpfIdKey,
        map_type: &'a BpfProgTypeKey,
        name: &'a BpfNameKey,
        prefix: &'a Key<BpfPrefixKey>,
    ) -> Self {
        Self {
            id_map,
            type_map,
            name_map,
            prefix_map,
            id,
            map_type,
            name,
            prefix,
        }
    }
}

impl CheckIn for BpfProgFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        match attribute_map_id {
            id if id == Attributes::ProgId as u8 => unsafe {
                let Some(mask_in) = self.id_map.get(self.id) else {
                    return Ok(false);
                };
                Ok(*mask_in & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::ProgType as u8 => unsafe {
                let Some(mask_in) = self.type_map.get(self.map_type) else {
                    return Ok(false);
                };

                Ok(*mask_in & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::ProgName as u8 => unsafe {
                let Some(mask_in) = self.name_map.get(self.name) else {
                    return Ok(false);
                };
                Ok(*mask_in & (1 << in_op_idx) != 0)
            },
            id if id == Attributes::ProgPrefix as u8 => {
                let Some(mask_in) = self.prefix_map.get(self.prefix) else {
                    return Ok(false);
                };
                Ok(*mask_in & (1 << in_op_idx) != 0)
            }
            _ => Err(0),
        }
    }
}
