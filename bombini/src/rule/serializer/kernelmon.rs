use bombini_common::config::rule::Attributes;

use crate::rule::serializer::attribute::AttributeMeta;

use crate::define_predicate;

define_predicate!(BpfMapPredicate {
    Attributes::MapId,
    Attributes::MapName,
    Attributes::MapType,
    Attributes::MapPrefix,
});

define_predicate!(BpfMapCreatePredicate {
    Attributes::MapName,
    Attributes::MapType,
    Attributes::MapPrefix,
});

define_predicate!(BpfProgPredicate {
    Attributes::ProgId,
    Attributes::ProgName,
    Attributes::ProgType,
    Attributes::ProgPrefix,
});

define_predicate!(BpfProgLoadPredicate {
    Attributes::ProgName,
    Attributes::ProgType,
    Attributes::ProgPrefix,
});
