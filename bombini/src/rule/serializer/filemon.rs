use bombini_common::config::rule::Attributes;

use crate::rule::serializer::attribute::AttributeMeta;

use crate::define_predicate;

define_predicate!(PathPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
});

// For now we have the same set of attributes for all hooks in FileMon. Let's use type aliasing.
pub type PathUnlinkPredicate = PathPredicate;
pub type PathTruncatePredicate = PathPredicate;
pub type SbMountPredicate = PathPredicate;

define_predicate!(FileOpenPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::AccessMode,
    Attributes::CreationFlags,
});

define_predicate!(PathSymlinkPredicate {
    Attributes::Path,
    Attributes::PathPrefix,
});

define_predicate!(PathChownPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::UID,
    Attributes::GID,
});

define_predicate!(FileIoctlPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::Cmd,
});

define_predicate!(PathChmodPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::Imode,
});

define_predicate!(MmapFilePredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::ProtMode,
    Attributes::MmapFlags,
});
