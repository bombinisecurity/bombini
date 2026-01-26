use aya_ebpf::{macros::map, maps::HashMap, maps::Array};

use crate::constants::MAX_FILE_PATH;

#[map]
pub static RULE_MAP: Array<Rule> =
    Array::with_max_entries(10, 0);

#[repr(C)]
pub struct Rule {
    pub scope: Predicate,
    pub event: Predicate,
}

type Predicate = [RuleOp; 64];

#[derive(Clone, Debug)]
#[repr(u8)]
pub enum RuleOp {
    Fin = 0,
    And,
    Or,
    Not,
    In {
        attribute_map_id: u32,
        in_op_idx: u64,
    }
}