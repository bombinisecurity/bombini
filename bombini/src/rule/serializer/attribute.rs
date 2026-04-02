use aya::Ebpf;
use bombini_common::config::rule::Attributes;

use crate::rule::ast::Literal;

pub mod defs;
mod util;

pub trait Attribute: std::fmt::Debug + std::any::Any {
    fn serialize(&mut self, values: &[Literal], in_idx: u8) -> Result<(), anyhow::Error>;
    fn store_attribute(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error>;
    fn get_attribute_map_size(&self, map_name_prefix: &str) -> (String, u32);
}

pub trait AttributeMeta {
    fn build(&self) -> Box<dyn Attribute>;
    fn name(&self) -> &'static str;
}

impl AttributeMeta for Attributes {
    fn build(&self) -> Box<dyn Attribute> {
        match self {
            Self::Path => Box::new(defs::PathAttribute::default()),
            Self::Name => Box::new(defs::NameAttribute::default()),
            Self::PathPrefix => Box::new(defs::PrefixAttribute::default()),
            Self::AccessMode => Box::new(defs::AccessModeAttribute::default()),
            Self::CreationFlags => Box::new(defs::CreationFlagsAttribute::default()),
            Self::UID => Box::new(defs::UIDAttribute::default()),
            Self::EUID => Box::new(defs::EUIDAttribute::default()),
            Self::GID => Box::new(defs::GIDAttribute::default()),
            Self::EGID => Box::new(defs::EGIDAttribute::default()),
            Self::Cmd => Box::new(defs::CmdAttribute::default()),
            Self::Imode => Box::new(defs::ImodeAttribute::default()),
            Self::ProtMode => Box::new(defs::ProtModeAttribute::default()),
            Self::MmapFlags => Box::new(defs::MmapFlagsAttribute::default()),
            Self::ECAPS => Box::new(defs::ECapsAttribute::default()),
            Self::PCAPS => Box::new(defs::PCapsAttribute::default()),
            Self::Ipv4Src => Box::new(defs::IPv4SrcAttribute::default()),
            Self::Ipv4Dst => Box::new(defs::IPv4DstAttribute::default()),
            Self::Ipv6Src => Box::new(defs::IPv6SrcAttribute::default()),
            Self::Ipv6Dst => Box::new(defs::IPv6DstAttribute::default()),
            Self::PortSrc => Box::new(defs::PortSrcAttribute::default()),
            Self::PortDst => Box::new(defs::PortDstAttribute::default()),
            Self::BinaryPath => Box::new(defs::BinaryPathAttribute::default()),
            Self::BinaryName => Box::new(defs::BinaryNameAttribute::default()),
            Self::BinaryPrefix => Box::new(defs::BinaryPrefixAttribute::default()),
            Self::MapType => Box::new(defs::BpfMapTypeAttribute::default()),
            Self::MapId => Box::new(defs::BpfIdAttribute::default()),
            Self::MapName => Box::new(defs::BpfNameAttribute::default()),
            Self::MapPrefix => Box::new(defs::BpfPrefixAttribute::default()),
            Self::ProgType => Box::new(defs::BpfProgTypeAttribute::default()),
            Self::ProgId => Box::new(defs::BpfIdAttribute::default()),
            Self::ProgName => Box::new(defs::BpfNameAttribute::default()),
            Self::ProgPrefix => Box::new(defs::BpfPrefixAttribute::default()),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Name => "name",
            Self::PathPrefix => "path_prefix",
            Self::AccessMode => "access_mode",
            Self::CreationFlags => "creation_flags",
            Self::UID => "uid",
            Self::EUID => "euid",
            Self::GID => "gid",
            Self::EGID => "egid",
            Self::Cmd => "cmd",
            Self::Imode => "mode",
            Self::ProtMode => "prot_mode",
            Self::MmapFlags => "flags",
            Self::ECAPS => "ecaps",
            Self::PCAPS => "pcaps",
            Self::Ipv4Src => "ipv4_src",
            Self::Ipv4Dst => "ipv4_dst",
            Self::Ipv6Src => "ipv6_src",
            Self::Ipv6Dst => "ipv6_dst",
            Self::PortSrc => "port_src",
            Self::PortDst => "port_dst",
            Self::BinaryPath => "binary_path",
            Self::BinaryName => "binary_name",
            Self::BinaryPrefix => "binary_prefix",
            Self::MapType | Self::ProgType => "type",
            Self::MapId | Self::ProgId => "id",
            Self::MapName | Self::ProgName => "name",
            Self::MapPrefix | Self::ProgPrefix => "prefix",
        }
    }
}
