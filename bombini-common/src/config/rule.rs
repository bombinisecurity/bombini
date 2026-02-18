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
#[repr(u8)]
pub enum ConnectionAttributes {
    Ipv4Src = 0,
    Ipv6Src,
    Ipv4Dst,
    Ipv6Dst,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum CredAttributes {
    UID = 0,
    EUID,
    GID,
    EGID,
    ECAPS,
    PCAPS,
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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Ipv4MapKey {
    pub rule_idx: u8,
    pub ip_addr: [u8; 4],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Ipv6MapKey {
    pub rule_idx: u8,
    pub ip_addr: [u8; 16],
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct UIDKey {
    pub rule_idx: u32,
    pub uid: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct CapKey {
    pub rule_idx: u8,
    pub in_idx: u8,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;
    use crate::event::process::Capabilities;

    unsafe impl aya::Pod for Rules {}
    unsafe impl aya::Pod for FileNameMapKey {}
    unsafe impl aya::Pod for PathPrefixMapKey {}
    unsafe impl aya::Pod for PathMapKey {}
    unsafe impl aya::Pod for Ipv4MapKey {}
    unsafe impl aya::Pod for Ipv6MapKey {}
    unsafe impl aya::Pod for UIDKey {}
    unsafe impl aya::Pod for CapKey {}
    unsafe impl aya::Pod for Capabilities {}
}
