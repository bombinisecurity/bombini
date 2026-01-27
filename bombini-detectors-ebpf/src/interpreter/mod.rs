use bombini_common::{config::rule::RuleOp, constants::MAX_RULE_OPERATIONS};

pub mod stack;

pub trait CheckIn {
    fn chech_in_op(&self, attribute_map_id: u8, in_op_idx: u64) -> Result<bool, i32>;
}
pub struct Interpreter<T> {
    stack: stack::Stack<'static, bool>,

    hook_attributes: T,
}

impl<T: CheckIn> Interpreter<T> {
    pub fn new(hook_attributes: T) -> Self {
        Self {
            stack: stack::Stack::new(),
            hook_attributes,
        }
    }

    pub fn check_predicate(
        &mut self,
        predicate: &[RuleOp; MAX_RULE_OPERATIONS],
    ) -> Result<bool, i32> {
        for op in predicate {
            match op {
                RuleOp::Fin => {
                    return self.stack.pop();
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
                            .chech_in_op(*attribute_map_id, *in_op_idx)?,
                    )?;
                }
            }
        }
        Err(0)
    }
}
