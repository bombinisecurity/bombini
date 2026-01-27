use bombini_common::config::rule::{Rule, RuleOp, Rules};

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
        matches!(self.scope[0], RuleOp::Fin) && matches!(self.event[0], RuleOp::Fin)
    }
}
