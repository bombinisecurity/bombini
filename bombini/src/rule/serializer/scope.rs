use bombini_common::config::rule::Attributes;

use crate::rule::serializer::attribute::AttributeMeta;

use crate::define_predicate;

define_predicate!(ScopePredicate {
    Attributes::BinaryPath,
    Attributes::BinaryName,
    Attributes::BinaryPrefix,
});
