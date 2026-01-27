use crate::constants::{MAX_RULE_OPERATIONS, MAX_RULES_COUNT};

#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct Rule {
    pub scope: Predicate,
    pub event: Predicate,
}

type Predicate = [RuleOp; MAX_RULE_OPERATIONS];

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum RuleOp {
    Fin = 0,
    And,
    Or,
    Not,
    In {
        attribute_map_id: u8,
        in_op_idx: u8,
    },
}

#[derive(Clone, Debug, Copy)]
pub struct Rules(Option<[Rule; MAX_RULES_COUNT]>);

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Rules {}
}
