use bombini_common::config::rule::{Predicate, Rule, RuleOp, Rules};

pub trait IsEmpty {
    fn is_empty(&self) -> bool;
}

impl IsEmpty for Rules {
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl IsEmpty for Rule {
    fn is_empty(&self) -> bool {
        self.scope.is_empty() && self.event.is_empty()
    }
}

impl IsEmpty for Predicate {
    fn is_empty(&self) -> bool {
        matches!(self[0], RuleOp::Fin)
    }
}
