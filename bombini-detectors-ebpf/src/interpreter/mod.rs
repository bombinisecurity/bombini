use bombini_common::{config::rule::RuleOp, constants::MAX_RULE_OPERATIONS};

pub mod rule;
pub mod stack;

pub trait CheckIn {
    fn chech_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32>;
}

pub struct Interpreter<T> {
    stack: stack::Stack<'static, bool>,

    hook_attributes: T,
}

impl<T: CheckIn> Interpreter<T> {
    pub fn new(hook_attributes: T) -> Result<Self, i32> {
        Ok(Self {
            stack: stack::Stack::new()?,
            hook_attributes,
        })
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

/*const STACK_SIZE: u32 = 64;

#[map]
static STACK_DATA: PerCpuArray<u64> = PerCpuArray::with_max_entries(STACK_SIZE, 0); // stack size must be equal to u64 size

#[map]
static STACK_LEN: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
pub struct Interpreter<T> {
    data_ptr: *mut u64,
    len_ptr: *mut u32,

    hook_attributes: T,
}

impl<T: CheckIn> Interpreter<T> {
    pub fn new(hook_attributes: T) -> Result<Self, i32> {
        let Some(data) = STACK_DATA.get_ptr_mut(0) else {
            return Err(0);
        };
        let Some(len) = STACK_LEN.get_ptr_mut(0) else {
            return Err(0);
        };
        unsafe {
            *data = 0;
            *len = 0;
        }
        Ok(Self {
            data_ptr: data,
            len_ptr: len,
            hook_attributes,
        })
    }

    pub fn check_predicate(
        &mut self,
        predicate: &[RuleOp; MAX_RULE_OPERATIONS],
    ) -> Result<bool, i32> {
        for op in predicate {
            match op {
                RuleOp::Fin => unsafe {
                    if *self.len_ptr == 0 {
                        return Err(0);
                    }
                    *self.len_ptr -= 1;
                    return Ok(*self.data_ptr & 1 << *self.len_ptr != 0);
                }
                RuleOp::And => unsafe {
                    if *self.len_ptr < 2 {
                        return Err(0);
                    }
                    // pop 2 elements from the stack and make an and operation
                    *self.len_ptr -= 2;
                    let shift = 3 << *self.len_ptr;
                    let result = (*self.data_ptr & shift == shift) as u64;

                    // Clear the current bit before setting the new value
                    *self.data_ptr &= !(1 << *self.len_ptr);
                    // Set the bit according to the result (0 or 1)
                    *self.data_ptr |= result << *self.len_ptr;
                    *self.len_ptr += 1;
                }
                RuleOp::Or => unsafe {
                    if *self.len_ptr < 2 {
                        return Err(0);
                    }
                    // pop 2 elements from the stack and make an or operation
                    *self.len_ptr -= 2;
                    let shift = 3 << *self.len_ptr;
                    let result = (*self.data_ptr & shift != 0) as u64;

                    // Clear the current bit before setting the new value
                    *self.data_ptr &= !(1 << *self.len_ptr);
                    // Set the bit according to the result (0 or 1)
                    *self.data_ptr |= result << *self.len_ptr;
                    *self.len_ptr += 1;
                }
                RuleOp::Not => unsafe {
                    if *self.len_ptr == 0 {
                        return Err(0);
                    }
                    // xor the last element with 1
                    let shift = 1 << (*self.len_ptr - 1);
                    *self.data_ptr ^= shift;
                }
                RuleOp::In {
                    attribute_map_id,
                    in_op_idx,
                } => unsafe {
                    if *self.len_ptr == STACK_SIZE {
                        return Err(0);
                    }
                    let result = self.hook_attributes
                            .chech_in_op(*attribute_map_id, *in_op_idx)? as u64;

                    // Clear the current bit before setting the new value
                    *self.data_ptr &= !(1 << *self.len_ptr);
                    // Set the bit according to the result (0 or 1)
                    *self.data_ptr |= result << *self.len_ptr;
                    *self.len_ptr += 1;
                }
                _ => {}
            }
        }
        Err(0)
    }
}*/
