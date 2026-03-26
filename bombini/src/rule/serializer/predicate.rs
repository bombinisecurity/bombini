#[macro_export]
macro_rules! define_predicate {
    ($name:ident { $($attr:expr),+ $(,)? }) => {
        #[derive(Debug)]
        pub struct $name {
            pub predicate: ::bombini_common::config::rule::Predicate,
            pub attrs: ::std::collections::HashMap<String, (Box<dyn $crate::rule::serializer::attribute::Attribute>, u8)>,
        }

        impl $name {
            pub fn new() -> Self {
                let mut instance = Self {
                    predicate: [::bombini_common::config::rule::RuleOp::Fin; ::bombini_common::constants::MAX_RULE_OPERATIONS],
                    attrs: ::std::collections::HashMap::new(),
                };

                $(
                    let attr = $attr.build();
                    instance.attrs.insert($attr.name().to_string(), (attr, $attr as u8));
                )+

                instance
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::rule::serializer::PredicateSerializer for $name {
            fn set_operation(&mut self, idx: u8, op: ::bombini_common::config::rule::RuleOp) {
                self.predicate[idx as usize] = op;
            }

            fn predicate(&self) -> ::bombini_common::config::rule::Predicate {
                self.predicate
            }

            fn serialize_attributes(
                &mut self,
                name: &str,
                values: &[$crate::rule::ast::Literal],
                in_idx: u8,
            ) -> Result<u8, anyhow::Error> {
                let (attr, attr_idx) = self.attrs
                    .get_mut(name)
                    .ok_or_else(|| anyhow::anyhow!("unknown attribute: {}", name))?;
                attr.serialize(values, in_idx)?;
                Ok(*attr_idx)
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

            fn attribute_map_sizes(&self, map_name_prefix: &str) -> ::std::collections::HashMap<String, u32> {
                let mut sizes = ::std::collections::HashMap::new();
                for (attr, _) in self.attrs.values() {
                    let (map_name, size) = attr.get_attribute_map_size(map_name_prefix);
                    sizes.insert(map_name, size);
                }
                sizes
            }
        }
    };
}
