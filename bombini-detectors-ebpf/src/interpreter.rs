use core::ffi::c_void;

use aya_ebpf::helpers::generated::bpf_loop;
use bombini_common::{
    config::rule::{Predicate, Rule, RuleOp},
    constants::{MAX_RULE_OPERATIONS, MAX_RULES_COUNT},
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
    // <VERIFIER_ISSUE>
    // Construction must stay infallible; do not wrap it in Result. An i32
    // error payload overlaps a map pointer of the hook attributes and LLVM
    // stores that pointer as two 32-bit halves, which the verifier rejects
    // as map_ptr arithmetic.
    pub fn new(hook_attributes: T) -> Self {
        Self { hook_attributes }
    }

    #[inline(always)]
    pub fn check_predicate(&mut self, predicate: &Predicate) -> Result<bool, i32> {
        if <Predicate as IsEmpty>::is_empty(predicate) {
            return Ok(true);
        }

        let mut ctx = PredicateLoopContext {
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
                rule_op_callback::<T> as *mut fn(u64, *mut c_void) -> i64 as *mut c_void,
                &mut ctx as *mut PredicateLoopContext<T> as *mut c_void,
                0,
            );
        }
        if ctx.error != 0 {
            return Err(ctx.error);
        }
        ctx.stack.pop()
    }
}

/// Calls `f` for every rule until the first empty one or until `f` returns
/// `Ok(true)` (stop) or an error.
///
/// <VERIFIER_ISSUE>
/// An open-coded rule loop is walked by the verifier for every rule index
/// and each iteration re-verifies the predicate bpf_loop callbacks, so on
/// kernel 7.0 hooks hit the 1M instructions limit (kernelmon bpf_map).
/// bpf_loop verifies the rule body once as a separate callback.
#[inline(always)]
pub fn for_each_rule<F>(rules: &[Rule; MAX_RULES_COUNT], f: F) -> Result<(), i32>
where
    F: FnMut(usize, &Rule) -> Result<bool, i32>,
{
    let mut ctx = RulesLoopContext { rules, f, error: 0 };
    unsafe {
        bpf_loop(
            MAX_RULES_COUNT as u32,
            rules_loop_callback::<F> as *mut fn(u64, *mut c_void) -> i64 as *mut c_void,
            &mut ctx as *mut RulesLoopContext<F> as *mut c_void,
            0,
        );
    }
    if ctx.error != 0 {
        return Err(ctx.error);
    }
    Ok(())
}

struct RulesLoopContext<'a, F> {
    rules: &'a [Rule; MAX_RULES_COUNT],
    f: F,
    error: i32,
}

unsafe fn rules_loop_callback<F>(idx: u64, data: *mut c_void) -> i64
where
    F: FnMut(usize, &Rule) -> Result<bool, i32>,
{
    let ctx = unsafe { &mut *(data as *mut RulesLoopContext<F>) };
    let idx = idx as usize;
    if idx >= MAX_RULES_COUNT {
        return 1;
    }
    let rule = &ctx.rules[idx];
    if rule.is_empty() {
        return 1;
    }
    match (ctx.f)(idx, rule) {
        Ok(false) => 0,
        Ok(true) => 1,
        Err(e) => {
            ctx.error = if e == 0 { -1 } else { e };
            1
        }
    }
}

struct PredicateLoopContext<'a, T> {
    stack: stack::Stack<bool>,
    hook_attributes: &'a T,
    predicate: &'a Predicate,
    error: i32,
}

impl<T: CheckIn> PredicateLoopContext<'_, T> {
    /// Executes a single operation. Returns false when the predicate is over.
    #[inline(always)]
    fn execute_rule_op(&mut self, idx: usize) -> Result<bool, i32> {
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

unsafe fn rule_op_callback<T: CheckIn>(idx: u64, data: *mut c_void) -> i64 {
    let ctx = unsafe { &mut *(data as *mut PredicateLoopContext<T>) };
    let idx = idx as usize;
    if idx >= MAX_RULE_OPERATIONS {
        return 1;
    }
    match ctx.execute_rule_op(idx) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            ctx.error = if e == 0 { -1 } else { e };
            1
        }
    }
}
