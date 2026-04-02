use crate::constants::{MAX_BPFNAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use crate::constants::{MAX_RULE_OPERATIONS, MAX_RULES_COUNT};
use crate::event::file::AccessMode;
use crate::event::kernel::{BpfMapType, BpfProgType};

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

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Attributes {
    Path = 0,
    PathPrefix,
    Name,
    BinaryPath,
    BinaryPrefix,
    BinaryName,
    // Filemon attributes
    CreationFlags,
    AccessMode,
    Imode,
    ProtMode,
    MmapFlags,
    Cmd,
    // Netmon attributes
    Ipv4Src,
    Ipv6Src,
    Ipv4Dst,
    Ipv6Dst,
    PortSrc,
    PortDst,
    // Procmon attributes
    UID,
    EUID,
    GID,
    EGID,
    ECAPS,
    PCAPS,
    // Kernelmon attributes
    MapType,
    MapId,
    MapName,
    MapPrefix,
    ProgType,
    ProgId,
    ProgName,
    ProgPrefix,
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
pub struct BpfNameKey {
    pub rule_idx: u8,
    pub name: [u8; MAX_BPFNAME_SIZE],
}

pub type BpfPrefixKey = BpfNameKey;

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
pub struct PortKey {
    pub rule_idx: u16,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct UintKey {
    pub rule_idx: u32,
    pub value: u32,
}

pub type UIDKey = UintKey;
pub type CmdKey = UintKey;
pub type BpfIdKey = UintKey;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BpfMapTypeKey {
    pub rule_idx: u32,
    pub map_type: BpfMapType,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BpfProgTypeKey {
    pub rule_idx: u32,
    pub prog_type: BpfProgType,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AccessModeKey {
    pub rule_idx: u32,
    pub access_mode: AccessMode,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct CapKey {
    pub rule_idx: u8,
    pub in_idx: u8,
}

pub type ImodeKey = CapKey;
pub type CreationFlagsKey = CapKey;
pub type ProtModeKey = CapKey;
pub type FlagsKey = CapKey;

#[cfg(feature = "user")]
pub mod user {
    use super::*;
    use crate::event::{
        file::{CreationFlags, Imode, ProtMode, SharingType},
        process::Capabilities,
    };

    unsafe impl aya::Pod for Rules {}
    unsafe impl aya::Pod for FileNameMapKey {}
    unsafe impl aya::Pod for PathPrefixMapKey {}
    unsafe impl aya::Pod for PathMapKey {}
    unsafe impl aya::Pod for Ipv4MapKey {}
    unsafe impl aya::Pod for Ipv6MapKey {}
    unsafe impl aya::Pod for UIDKey {}
    unsafe impl aya::Pod for CapKey {}
    unsafe impl aya::Pod for Capabilities {}
    unsafe impl aya::Pod for PortKey {}
    unsafe impl aya::Pod for Imode {}
    unsafe impl aya::Pod for CreationFlags {}
    unsafe impl aya::Pod for AccessModeKey {}
    unsafe impl aya::Pod for ProtMode {}
    unsafe impl aya::Pod for SharingType {}
    unsafe impl aya::Pod for BpfNameKey {}
    unsafe impl aya::Pod for BpfMapTypeKey {}
    unsafe impl aya::Pod for BpfProgTypeKey {}
}
