use crate::constants::MAX_RULE_OPERATIONS;

#[repr(C)]
pub struct Rule {
    pub scope: Predicate,
    pub event: Predicate,
}

type Predicate = [RuleOp; MAX_RULE_OPERATIONS];

#[derive(Clone, Debug)]
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
