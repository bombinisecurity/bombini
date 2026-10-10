use core::ffi::c_void;

use aya_ebpf::helpers::generated::bpf_loop;
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
    hook_attributes: T,
}

impl<T: CheckIn> Interpreter<T> {
    pub fn new(hook_attributes: T) -> Result<Self, i32> {
        // <VERIFIER_ISSUE>
        // Keep construction infallible, so the Result is optimized out.
        // Otherwise the i32 error payload overlaps a map pointer of the hook
        // attributes and LLVM stores that pointer as two 32-bit halves, which
        // the verifier rejects as map_ptr arithmetic.
        Ok(Self { hook_attributes })
    }

    #[inline(always)]
    pub fn check_predicate(&mut self, predicate: &Predicate) -> Result<bool, i32> {
        if <Predicate as IsEmpty>::is_empty(predicate) {
            return Ok(true);
        }

        let mut ctx = LoopContext {
            stack: stack::Stack::new()?,
            hook_attributes: &self.hook_attributes,
            predicate,
            error: 0,
        };

        // <VERIFIER_ISSUE>
        // An open-coded loop is walked by the verifier for every operation
        // index, so on kernel 7.0 hooks with several rule loops (kernelmon
        // bpf_map_create) hit the 1M instructions limit. bpf_loop verifies
        // the loop body once as a separate callback.
        unsafe {
            bpf_loop(
                MAX_RULE_OPERATIONS as u32,
                execute_op_callback::<T> as *mut fn(u64, *mut c_void) -> i64 as *mut c_void,
                &mut ctx as *mut LoopContext<T> as *mut c_void,
                0,
            );
        }
        if ctx.error != 0 {
            return Err(ctx.error);
        }
        ctx.stack.pop()
    }
}

struct LoopContext<'a, T> {
    stack: stack::Stack<bool>,
    hook_attributes: &'a T,
    predicate: &'a Predicate,
    error: i32,
}

impl<T: CheckIn> LoopContext<'_, T> {
    /// Executes a single operation. Returns false when the predicate is over.
    #[inline(always)]
    fn execute_op(&mut self, idx: usize) -> Result<bool, i32> {
        match &self.predicate[idx] {
            RuleOp::Fin => return Ok(false),
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
        Ok(true)
    }
}

unsafe fn execute_op_callback<T: CheckIn>(idx: u64, data: *mut c_void) -> i64 {
    let ctx = unsafe { &mut *(data as *mut LoopContext<T>) };
    let idx = idx as usize;
    if idx >= MAX_RULE_OPERATIONS {
        return 1;
    }
    match ctx.execute_op(idx) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            ctx.error = if e == 0 { -1 } else { e };
            1
        }
    }
}
