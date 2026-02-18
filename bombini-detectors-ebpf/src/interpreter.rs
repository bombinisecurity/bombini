#![allow(clippy::needless_range_loop)]

use bombini_common::{
    config::rule::{Predicate, RuleOp},
    constants::MAX_RULE_OPERATIONS,
};

use crate::interpreter::rule::IsEmpty;

pub mod rule;
pub mod stack;

pub trait CheckIn {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32>;
}

pub struct Interpreter<T> {
    stack: stack::Stack<bool>,

    hook_attributes: T,
}

impl<T: CheckIn> Interpreter<T> {
    pub fn new(hook_attributes: T) -> Result<Self, i32> {
        Ok(Self {
            stack: stack::Stack::new()?,
            hook_attributes,
        })
    }

    #[inline(always)]
    pub fn check_predicate(&mut self, predicate: &Predicate) -> Result<bool, i32> {
        if <Predicate as IsEmpty>::is_empty(predicate) {
            return Ok(true);
        }

        // No iterator here because of verifier issues
        let mut idx = 0;
        while idx < MAX_RULE_OPERATIONS {
            let op = &predicate[idx];
            match op {
                RuleOp::Fin => {
                    idx = MAX_RULE_OPERATIONS;
                }
                RuleOp::And => {
                    let a = self.stack.pop()?;
                    let b = self.stack.pop()?;
                    self.stack.push(a && b)?;
                }
                RuleOp::Or => {
                    let a = self.stack.pop()?;
                    let b = self.stack.pop()?;
                    self.stack.push(a || b)?;
                }
                RuleOp::Not => {
                    let a = self.stack.pop()?;
                    self.stack.push(!a)?;
                }
                RuleOp::In {
                    attribute_map_id,
                    in_op_idx,
                } => {
                    self.stack.push(
                        self.hook_attributes
                            .check_in_op(*attribute_map_id, *in_op_idx)?,
                    )?;
                }
            }
            idx += 1;
        }
        self.stack.pop()
    }
}
