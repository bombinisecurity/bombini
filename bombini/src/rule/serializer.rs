use aya::Ebpf;
use aya::maps::Array;

use bombini_common::{
    config::rule::{Predicate, Rule as BinaryRule, RuleOp, Rules as BinaryRules},
    constants::{MAX_RULE_OPERATIONS, MAX_RULES_COUNT},
};

use std::collections::HashMap;
use std::fmt::Debug;

use crate::proto::config::Rule;
use crate::rule::ast::{Expr, Literal};
use crate::rule::predicate;

pub mod filemon;
pub mod scope;

use scope::ScopePredicate;

pub trait PredicateSerializer {
    fn serialize_attributes(
        &mut self,
        name: &str,
        values: &[Literal],
        in_idx: u8,
    ) -> Result<u8, anyhow::Error>;
    fn set_operation(&mut self, idx: u8, op: RuleOp);
    fn predicate(&self) -> Predicate;
    fn store_attributes(
        &self,
        ebpf: &mut Ebpf,
        rule_idx: u8,
        map_name_prefix: &str,
    ) -> Result<(), anyhow::Error>;
    fn attribute_map_sizes(&self, map_name_prefix: &str) -> HashMap<String, u32>;
}

struct RpnConverter {
    in_counter: u8,
    op_idx: u8,
}

impl RpnConverter {
    pub fn new() -> Self {
        Self {
            in_counter: 0,
            op_idx: 0,
        }
    }

    pub fn convert_expr<T: PredicateSerializer>(
        &mut self,
        serializer: &mut T,
        expr: &Expr,
    ) -> Result<(), anyhow::Error> {
        if self.op_idx as usize >= MAX_RULE_OPERATIONS {
            return Err(anyhow::anyhow!(
                "max rule operations: {MAX_RULE_OPERATIONS} is exceeded"
            ));
        }
        match expr {
            Expr::Or(left, right) => {
                self.convert_expr(serializer, left)?;
                self.convert_expr(serializer, right)?;
                serializer.set_operation(self.op_idx, RuleOp::Or);
            }
            Expr::And(left, right) => {
                self.convert_expr(serializer, left)?;
                self.convert_expr(serializer, right)?;
                serializer.set_operation(self.op_idx, RuleOp::And);
            }
            Expr::Not(inner) => {
                self.convert_expr(serializer, inner)?;
                serializer.set_operation(self.op_idx, RuleOp::Not);
            }
            Expr::Eq(attribute, literal) => {
                // Treat Eq as In with one element
                let id = serializer.serialize_attributes(
                    attribute.as_str(),
                    std::slice::from_ref(literal),
                    self.in_counter,
                )?;
                let op = RuleOp::In {
                    attribute_map_id: id,
                    in_op_idx: self.in_counter,
                };
                serializer.set_operation(self.op_idx, op);
                self.in_counter += 1;
            }
            Expr::In(attribute, literals) => {
                let id = serializer.serialize_attributes(
                    attribute.as_str(),
                    &literals[..],
                    self.in_counter,
                )?;
                let op = RuleOp::In {
                    attribute_map_id: id,
                    in_op_idx: self.in_counter,
                };
                serializer.set_operation(self.op_idx, op);
                self.in_counter += 1;
            }
            Expr::Group(inner) => {
                self.convert_expr(serializer, inner)?;
                return Ok(());
            }
        }
        self.op_idx += 1;
        Ok(())
    }
}

#[derive(Debug)]
struct SerializedRule<T>
where
    T: PredicateSerializer + std::fmt::Debug,
{
    scope_predicate: ScopePredicate,
    event_predicate: T,
}

impl<T> SerializedRule<T>
where
    T: PredicateSerializer + std::fmt::Debug,
{
    pub fn serialize_rule(&mut self, rule: &Rule) -> Result<(), anyhow::Error> {
        if !rule.scope.is_empty() {
            let Ok(ast) = predicate::ExprParser::new().parse(&rule.scope) else {
                return Err(anyhow::anyhow!("failed to parse ast for: {}", &rule.scope));
            };
            let ast = ast.optimize_ast();
            let mut converter = RpnConverter::new();
            converter.convert_expr(&mut self.scope_predicate, &ast)?;
        }

        if !rule.event.is_empty() {
            let Ok(ast) = predicate::ExprParser::new().parse(&rule.event) else {
                return Err(anyhow::anyhow!("failed to parse ast for: {}", &rule.event));
            };
            let ast = ast.optimize_ast();
            let mut converter = RpnConverter::new();
            converter.convert_expr(&mut self.event_predicate, &ast)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
#[derive(Debug)]
pub struct SerializedRules<T>
where
    T: PredicateSerializer + std::fmt::Debug,
{
    rules: Vec<SerializedRule<T>>,
}

impl<T> SerializedRules<T>
where
    T: PredicateSerializer + Default + std::fmt::Debug,
    T: PredicateSerializer,
{
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn serialize_rules(&mut self, rules: &[Rule]) -> Result<(), anyhow::Error>
    where
        T: Default,
    {
        self.rules.clear();

        if rules.len() > MAX_RULES_COUNT {
            return Err(anyhow::anyhow!(
                "Rules count is exceeded. {} > {}",
                rules.len(),
                MAX_RULES_COUNT
            ));
        }

        for rule in rules.iter() {
            let mut serialized_rule = SerializedRule {
                scope_predicate: ScopePredicate::new(),
                event_predicate: T::default(),
            };

            serialized_rule.serialize_rule(rule)?;
            self.rules.push(serialized_rule);
        }
        Ok(())
    }

    pub fn store_rules(
        &self,
        ebpf: &mut Ebpf,
        map_name_prefix: &'static str,
    ) -> Result<(), anyhow::Error> {
        self.store_predicates(ebpf, &format!("{}_RULE_MAP", map_name_prefix))?;
        for (i, rule) in self.rules.iter().take(MAX_RULES_COUNT).enumerate() {
            rule.scope_predicate
                .store_attributes(ebpf, i as u8, map_name_prefix)?;
            rule.event_predicate
                .store_attributes(ebpf, i as u8, map_name_prefix)?;
        }
        Ok(())
    }

    fn store_predicates(&self, ebpf: &mut Ebpf, rule_map_name: &str) -> Result<(), anyhow::Error> {
        let mut map: Array<_, BinaryRules> = Array::try_from(ebpf.map_mut(rule_map_name).unwrap())?;
        if self.rules.is_empty() {
            let _ = map.set(0, BinaryRules(None), 0);
            return Ok(());
        }
        let mut rules = [BinaryRule {
            scope: [RuleOp::Fin; MAX_RULE_OPERATIONS],
            event: [RuleOp::Fin; MAX_RULE_OPERATIONS],
        }; MAX_RULES_COUNT];
        for (i, rule) in self.rules.iter().take(MAX_RULES_COUNT).enumerate() {
            rules[i] = BinaryRule {
                scope: rule.scope_predicate.predicate(),
                event: rule.event_predicate.predicate(),
            };
        }
        let _ = map.set(0, BinaryRules(Some(rules)), 0);
        Ok(())
    }

    pub fn map_sizes(&self, map_name_prefix: &'static str) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert(
            format!("{}_RULE_MAP", map_name_prefix),
            self.rules.len().max(1) as u32,
        );
        for rule in self.rules.iter().take(MAX_RULES_COUNT) {
            rule.scope_predicate
                .attribute_map_sizes(map_name_prefix)
                .iter()
                .for_each(|(k, v)| {
                    *map.entry(k.to_string()).or_insert(1) += v;
                });
            rule.event_predicate
                .attribute_map_sizes(map_name_prefix)
                .iter()
                .for_each(|(k, v)| {
                    *map.entry(k.to_string()).or_insert(1) += v;
                });
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::config::Rule;

    #[test]
    fn test_or_fold_ast_optimization() {
        let rules = vec![Rule {
            name: "".to_string(),
            scope: "".to_string(),
            event: r#"path == "/var" OR (path in ["/var", "/log"] OR path == "/tmp")"#.to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::FileOpenPredicate> { rules: Vec::new() };

        let _ = serialized.serialize_rules(&rules).unwrap();
        let map_sizes = serialized.map_sizes("FILEMON_OPEN");
        assert_eq!(map_sizes.get("FILEMON_OPEN_PATH_MAP"), Some(&3));

        let rule0 = &serialized.rules[0];
        // Optimized In
        match rule0.event_predicate.predicate[0] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::rule::ScopeAttributes::BinaryPath as u8
                );
                assert_eq!(in_op_idx, 0);
            }
            _ => panic!("Expected RuleOp::In in event predicate[0]"),
        }
        assert_eq!(*rule0.event_predicate.path_map.get("/var").unwrap(), 1 << 0);
        assert_eq!(*rule0.event_predicate.path_map.get("/log").unwrap(), 1 << 0);
        assert_eq!(*rule0.event_predicate.path_map.get("/tmp").unwrap(), 1 << 0);
    }

    #[test]
    fn test_serialize_rules_success() {
        let rules = vec![
            Rule {
                name: "".to_string(),
                scope: "binary_path == \"/usr/bin/ls\"".to_string(),
                event: "path == \"/etc/passwd\" AND path in [\"/etc/passwd\", \"/etc/shadow\"]"
                    .to_string(),
            },
            Rule {
                name: "test_rule_2".to_string(),
                scope: "binary_name in [\"cat\", \"grep\"]".to_string(),
                event: "name in [\"shadow\", \"passwd\"]".to_string(),
            },
        ];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let _ = serialized.serialize_rules(&rules).unwrap();
        assert_eq!(serialized.rules.len(), 2);
        let map_sizes = serialized.map_sizes("FILEMON_OPEN");
        assert_eq!(map_sizes.get("FILEMON_OPEN_NAME_MAP"), Some(&2));
        assert_eq!(map_sizes.get("FILEMON_OPEN_BINPATH_MAP"), Some(&1));
        assert_eq!(map_sizes.get("FILEMON_OPEN_BINPREFIX_MAP"), Some(&0));
        assert_eq!(map_sizes.get("FILEMON_OPEN_PATH_MAP"), Some(&2));
        assert_eq!(map_sizes.get("FILEMON_OPEN_RULE_MAP"), Some(&2));
        assert_eq!(map_sizes.get("FILEMON_OPEN_PREFIX_MAP"), Some(&0));
        assert_eq!(map_sizes.get("FILEMON_OPEN_BINNAME_MAP"), Some(&2));

        let rule0 = &serialized.rules[0];

        // Scope: binary_path == "/usr/bin/ls"
        assert_eq!(rule0.scope_predicate.binary_path_map.len(), 1);
        assert_eq!(
            *rule0
                .scope_predicate
                .binary_path_map
                .get("/usr/bin/ls")
                .unwrap(),
            1 << 0
        );
        match rule0.scope_predicate.predicate[0] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::rule::ScopeAttributes::BinaryPath as u8
                );
                assert_eq!(in_op_idx, 0);
            }
            _ => panic!("Expected RuleOp::In in scope predicate[0]"),
        }

        assert_eq!(rule0.event_predicate.path_map.len(), 2);
        assert_eq!(
            *rule0.event_predicate.path_map.get("/etc/passwd").unwrap(),
            1 << 0 | 1 << 1
        );
        match rule0.event_predicate.predicate[0] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::filemon::PathAttributes::Path as u8
                );
                assert_eq!(in_op_idx, 0);
            }
            _ => panic!("Expected RuleOp::In in event predicate[0]"),
        }

        let rule1 = &serialized.rules[1];

        assert_eq!(rule1.scope_predicate.binary_name_map.len(), 2);
        assert_eq!(
            *rule1.scope_predicate.binary_name_map.get("cat").unwrap(),
            1 << 0
        );
        assert_eq!(
            *rule1.scope_predicate.binary_name_map.get("grep").unwrap(),
            1 << 0
        );

        assert_eq!(rule1.event_predicate.name_map.len(), 2);
        assert_eq!(
            *rule1.event_predicate.name_map.get("shadow").unwrap(),
            1 << 0
        );
        assert_eq!(
            *rule1.event_predicate.name_map.get("passwd").unwrap(),
            1 << 0
        );

        assert!(rule1.scope_predicate.binary_path_map.is_empty());
        assert!(rule1.event_predicate.path_map.is_empty());
    }

    #[test]
    fn test_serialize_rules_scope_parse_error() {
        let rules = vec![Rule {
            name: "bad_rule".to_string(),
            scope: "binary_path ==".to_string(), // invalid syntax
            event: "path == \"/tmp\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to parse ast")
        );
    }

    #[test]
    fn test_serialize_rules_invalid_scope_attribute() {
        let rules = vec![Rule {
            name: "invalid_attr_rule".to_string(),
            scope: "invalid_attr == \"value\"".to_string(),
            event: "path == \"/tmp\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid scope attribute name")
        );
    }

    #[test]
    fn test_serialize_rules_invalid_event_attribute() {
        let rules = vec![Rule {
            name: "invalid_event_attr".to_string(),
            scope: "binary_path == \"/bin/sh\"".to_string(),
            event: "invalid_attr == \"value\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid scope attribute name")
        );
    }

    #[test]
    fn test_serialize_rules_uint_literal_in_scope() {
        let rules = vec![Rule {
            name: "uint_in_scope".to_string(),
            scope: "binary_path == 123".to_string(), // Uint instead of String
            event: "path == \"/tmp\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected String literal, found Uint")
        );
    }

    #[test]
    fn test_serialize_rules_only_scope() {
        let rules = vec![Rule {
            name: "only_scope".to_string(),
            scope: "binary_name == \"sh\"".to_string(),
            event: "".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_ok());
        assert_eq!(serialized.rules.len(), 1);

        let rule = &serialized.rules[0];
        assert_eq!(rule.scope_predicate.binary_name_map.len(), 1);
        assert!(rule.event_predicate.path_map.is_empty());
        assert!(rule.event_predicate.name_map.is_empty());
        assert!(rule.event_predicate.path_prefix_map.is_empty());
    }

    #[test]
    fn test_serialize_rules_only_event() {
        let rules = vec![Rule {
            name: "only_event".to_string(),
            scope: "".to_string(),
            event: "name == \"important.log\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_ok());
        assert_eq!(serialized.rules.len(), 1);

        let rule = &serialized.rules[0];
        assert_eq!(rule.event_predicate.name_map.len(), 1);
        assert!(rule.scope_predicate.binary_path_map.is_empty());
        assert!(rule.scope_predicate.binary_name_map.is_empty());
        assert!(rule.scope_predicate.binary_prefix_map.is_empty());
    }

    #[test]
    fn test_serialize_rules_with_logical_ops() {
        let rules = vec![Rule {
            name: "logical_ops".to_string(),
            scope:
                "(binary_path == \"/bin/sh\" AND binary_name == \"sh\") OR binary_name == \"zsh\""
                    .to_string(),
            event: "path == \"/secret\" OR name == \"key\"".to_string(),
        }];

        let mut serialized = SerializedRules::<filemon::PathPredicate> { rules: Vec::new() };

        let result = serialized.serialize_rules(&rules);
        assert!(result.is_ok());
        assert_eq!(serialized.rules.len(), 1);

        let rule = &serialized.rules[0];

        // Scope: In, In, And, In, Or
        match rule.scope_predicate.predicate[0] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::rule::ScopeAttributes::BinaryPath as u8
                );
                assert_eq!(in_op_idx, 0);
            }
            _ => panic!("Expected In at scope[0]"),
        }
        match rule.scope_predicate.predicate[1] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::rule::ScopeAttributes::BinaryName as u8
                );
                assert_eq!(in_op_idx, 1);
            }
            _ => panic!("Expected In at scope[1]"),
        }
        assert_eq!(rule.scope_predicate.predicate[2], RuleOp::And);
        match rule.scope_predicate.predicate[3] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::rule::ScopeAttributes::BinaryName as u8
                );
                assert_eq!(in_op_idx, 2);
            }
            _ => panic!("Expected In at scope[3]"),
        }
        assert_eq!(rule.scope_predicate.predicate[4], RuleOp::Or);

        // Event: In, In, Or
        match rule.event_predicate.predicate[0] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::filemon::PathAttributes::Path as u8
                );
                assert_eq!(in_op_idx, 0);
            }
            _ => panic!("Expected In at event[0]"),
        }
        match rule.event_predicate.predicate[1] {
            RuleOp::In {
                attribute_map_id,
                in_op_idx,
            } => {
                assert_eq!(
                    attribute_map_id,
                    bombini_common::config::filemon::PathAttributes::Name as u8
                );
                assert_eq!(in_op_idx, 1);
            }
            _ => panic!("Expected In at event[1]"),
        }
        assert_eq!(rule.event_predicate.predicate[2], RuleOp::Or);
    }
}
