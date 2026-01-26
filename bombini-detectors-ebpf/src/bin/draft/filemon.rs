#![no_std]
#![no_main]

use aya_ebpf::{
    bpf_printk,
    helpers::bpf_d_path,
    macros::{lsm, map},
    maps::{hash_map::HashMap, per_cpu_array::PerCpuArray},
    programs::LsmContext,
};
use bombini_common::{
    constants::MAX_FILE_PATH,
    draft::rule_interface::{RULE_MAP, RuleOp},
};
use bombini_detectors_ebpf::vmlinux::file;

struct Stack<T, const N: u32> {
    data: PerCpuArray<T>,
    len: PerCpuArray<u32>,
}

impl<T: Copy, const N: u32> Stack<T, N> {
    const fn new() -> Self {
        Self {
            data: PerCpuArray::with_max_entries(N as u32, 0),
            len: PerCpuArray::with_max_entries(1, 0),
        }
    }

    fn push(&self, value: T) -> Result<(), ()> {
        let len = self.len.get(0).ok_or(())?;
        if *len >= N {
            return Err(());
        }
        unsafe {
            *self.data.get_ptr_mut(*len).ok_or(())? = value;
            *self.len.get_ptr_mut(0).ok_or(())? = len + 1;
        }
        Ok(())
    }

    fn pop(&self) -> Result<T, ()> {
        let len = self.len.get(0).ok_or(())?;
        if *len == 0 {
            return Err(());
        }
        let value = self.data.get(*len - 1).ok_or(())?.clone();
        unsafe {
            *self.len.get_ptr_mut(0).ok_or(())? = len - 1;
        }
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.len.get(0).map(|&len| len == 0).unwrap_or(true)
    }

    fn len(&self) -> u32 {
        self.len.get(0).copied().unwrap_or(0)
    }
}

#[map]
static STACK: Stack<bool, 1024> = Stack::new();

#[map]
static FILEMON_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> = HashMap::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "file_open")]
fn file_open_capture_modified(ctx: LsmContext) -> i32 {
    let rule = RULE_MAP.get(0).unwrap();

    if !(check_predicate(&rule.scope, &ctx) && check_predicate(&rule.event, &ctx)) {
        return 0;
    }

    unsafe { bpf_printk!(b"file_open_capture_modified: %d\n", 1) };

    0
}

fn check_predicate(predicate: &[RuleOp; 64], ctx: &LsmContext) -> bool {
    for op in predicate {
        match op {
            RuleOp::Fin => return STACK.pop().unwrap(),
            RuleOp::And => {
                let a = STACK.pop().unwrap();
                let b = STACK.pop().unwrap();
                STACK.push(a && b).unwrap();
            }
            RuleOp::Or => {
                let a = STACK.pop().unwrap();
                let b = STACK.pop().unwrap();
                STACK.push(a || b).unwrap();
            }
            RuleOp::Not => {
                let a = STACK.pop().unwrap();
                STACK.push(!a).unwrap();
            }
            RuleOp::In {
                attribute_map_id: _,
                in_op_idx,
            } => unsafe {
                let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
                    return false;
                };
                let fp: *const file = ctx.arg(0);
                let _ = bpf_d_path(
                    &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
                    path_ptr as *mut _,
                    MAX_FILE_PATH as u32,
                );
                let attr_mask = FILEMON_BINPATH_MAP.get(&*(path_ptr as *const _)).unwrap();
                if attr_mask & (1 << *in_op_idx) != 0 {
                    STACK.push(true).unwrap();
                } else {
                    STACK.push(false).unwrap();
                }
            },
        }
    }
    false
}
