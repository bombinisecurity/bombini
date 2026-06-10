use anyhow::bail;
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

define_predicate!(BprmCheckPredicate {
    Attributes::Path,
    Attributes::Name,
    Attributes::PathPrefix,
    Attributes::EUID,
    Attributes::EGID,
    Attributes::ECAPS,
});

const MAX_ARGS_ATTRIBUTES: usize = 32;

#[derive(Debug)]
pub struct ExecveSandboxPredicate {
    pub predicate: ::bombini_common::config::rule::Predicate,
    pub attrs: ::std::collections::HashMap<
        String,
        (Box<dyn crate::rule::serializer::attribute::Attribute>, u8),
    >,
}

impl ExecveSandboxPredicate {
    pub fn new() -> Self {
        let mut instance = Self {
            predicate: [::bombini_common::config::rule::RuleOp::Fin;
                ::bombini_common::constants::MAX_RULE_OPERATIONS],
            attrs: ::std::collections::HashMap::new(),
        };

        for i in 0..MAX_ARGS_ATTRIBUTES {
            let attr = Attributes::Arg.build();
            instance.attrs.insert(
                Attributes::Arg.name().to_string() + &i.to_string(),
                (attr, i as u8),
            );
        }

        instance
    }
}

impl Default for ExecveSandboxPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::rule::serializer::PredicateSerializer for ExecveSandboxPredicate {
    fn set_operation(&mut self, idx: u8, op: ::bombini_common::config::rule::RuleOp) {
        self.predicate[idx as usize] = op;
    }

    fn predicate(&self) -> ::bombini_common::config::rule::Predicate {
        self.predicate
    }

    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[crate::rule::ast::Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error> {
        let (attr, arg_num) = self
            .attrs
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("unknown attribute: {}", name))?;

        let new_in_idx = in_idx as usize + 8 * *arg_num as usize;
        if new_in_idx > u8::MAX as usize {
            bail!("IN operation index is too large for argument: {}", name);
        }

        attr.serialize(values, new_in_idx as u8)?;
        // Return IN operation index instead of attribute index
        // This is because we need to distinguish between different arguments which are the single attribute in code
        Ok(new_in_idx as u8)
    }

    fn store_attributes(
        &self,
        ebpf: &mut ::aya::Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error> {
        for (attr, _) in self.attrs.values() {
            attr.store_attribute(ebpf, rule_idx, map_name_prefix)?;
        }
        Ok(())
    }

    fn attribute_map_sizes(
        &self,
        map_name_prefix: &str,
    ) -> ::std::collections::HashMap<String, u32> {
        let mut sizes = ::std::collections::HashMap::new();
        for (attr, _) in self.attrs.values() {
            let (map_name, size) = attr.get_attribute_map_size(map_name_prefix);
            *sizes.entry(map_name).or_insert(0) += size;
        }
        sizes
    }
}
