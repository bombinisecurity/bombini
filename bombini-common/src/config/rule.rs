use crate::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use crate::constants::{MAX_RULE_OPERATIONS, MAX_RULES_COUNT};

#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct Rule {
    pub scope: Predicate,
    pub event: Predicate,
}

pub type Predicate = [RuleOp; MAX_RULE_OPERATIONS];

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum RuleOp {
    Fin = 0,
    And,
    Or,
    Not,
    In { attribute_map_id: u8, in_op_idx: u8 },
}

#[derive(Clone, Debug, Copy)]
pub struct Rules(pub Option<[Rule; MAX_RULES_COUNT]>);

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ScopeAttributes {
    BinaryPath = 0,
    BinaryPrefix,
    BinaryName,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum PathAttributes {
    Path = 0,
    PathPrefix,
    Name,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileNameMapKey {
    pub rule_idx: u8,
    pub name: [u8; MAX_FILENAME_SIZE],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PathMapKey {
    pub rule_idx: u8,
    pub path: [u8; MAX_FILE_PATH],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PathPrefixMapKey {
    pub rule_idx: u8,
    pub path_prefix: [u8; MAX_FILE_PREFIX],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for Rules {}
    unsafe impl aya::Pod for FileNameMapKey {}
    unsafe impl aya::Pod for PathPrefixMapKey {}
    unsafe impl aya::Pod for PathMapKey {}
}
