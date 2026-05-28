use bombini_common::config::rule::Attributes;

use crate::rule::serializer::attribute::AttributeMeta;

use crate::define_predicate;

define_predicate!(TcpConnectionPredicate {
    Attributes::Ipv4Src,
    Attributes::Ipv4Dst,
    Attributes::Ipv6Src,
    Attributes::Ipv6Dst,
    Attributes::PortSrc,
    Attributes::PortDst,
});

define_predicate!(SocketCreatePredicate {
    Attributes::SockFamily,
    Attributes::SockType,
    Attributes::SockFlags,
});
