use crate::constants::MAX_RULE_OPERATIONS;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Rule {
    pub scope: Predicate,
    pub event: Predicate,
}

pub type Predicate = [RuleOp; MAX_RULE_OPERATIONS];

#[derive(Clone, Debug, Copy)]
#[repr(u8)]
pub enum RuleOp {
    Fin = 0,
    And,
    Or,
    Not,
    In {
        attribute_map_id: u8,
        in_op_idx: u64,
    },
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Rule {}
}
