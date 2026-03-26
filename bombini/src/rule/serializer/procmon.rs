use bombini_common::config::rule::Attributes;

use crate::rule::serializer::attribute::AttributeMeta;

use crate::define_predicate;

define_predicate!(UidPredicate {
    Attributes::UID,
    Attributes::EUID,
});

define_predicate!(GidPredicate {
    Attributes::GID,
    Attributes::EGID,
});

define_predicate!(CapPredicate {
    Attributes::ECAPS,
    Attributes::PCAPS,
});

define_predicate!(CredPredicate {
    Attributes::ECAPS,
    Attributes::EUID,
});
