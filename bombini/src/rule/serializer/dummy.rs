use std::collections::HashMap;

use anyhow::bail;
use aya::Ebpf;
use bombini_common::{
    config::rule::{Predicate, RuleOp},
    constants::MAX_RULE_OPERATIONS,
};

use crate::rule::{ast::Literal, serializer::PredicateSerializer};

#[derive(Debug)]
pub struct DummyPredicate {
    predicate: Predicate,
}

impl DummyPredicate {
    pub fn new() -> Self {
        Self {
            predicate: [RuleOp::Fin; MAX_RULE_OPERATIONS],
        }
    }
}

impl Default for DummyPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl PredicateSerializer for DummyPredicate {
    fn set_operation(&mut self, idx: u8, op: RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        _values: &[Literal],
        _in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        bail!("Attribute {name} is not supported");
    }

    fn store_attributes(
        &self,
        _ebpf: &mut Ebpf,
        _rule_idx: u8,
        _map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn attribute_map_sizes(&self, _map_name_prefix: &str) -> HashMap<String, u32> {
        HashMap::new()
    }
}
