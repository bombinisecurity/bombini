//! Credentials filters for bprm check

use aya_ebpf::{bpf_printk, maps::{HashMap, PerCpuHashMap}};
use bombini_common::{
    config::rule::{Attributes, CapKey, ExecArgKey, UIDKey}, constants::{MAX_ARG_SIZE, MAX_ARGS_COUNT}, event::process::Capabilities
};

use crate::{filter::procmon::cred::CapValue, interpreter::CheckIn};
use aya_ebpf::maps::{LpmTrie, lpm_trie::Key};
use bombini_common::config::rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey};

#[repr(C)]
pub struct SchedProcessExecFilter<'a> {
    pub args_map: &'a HashMap<ExecArgKey, [[u8; MAX_ARG_SIZE]; MAX_ARGS_COUNT]>,

    pub args: &'a PerCpuHashMap<[u8; MAX_ARG_SIZE], u8>,
    pub rule_idx: u8,
}

impl<'a> SchedProcessExecFilter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        args_map: &'a HashMap<ExecArgKey, [[u8; MAX_ARG_SIZE]; MAX_ARGS_COUNT]>,

        args: &'a PerCpuHashMap<[u8; MAX_ARG_SIZE], u8>,
        rule_idx: u8,
    ) -> Self {
        Self {
            args_map,
            args,
            rule_idx,
        }
    }
}

impl CheckIn for SchedProcessExecFilter<'_> {
    fn check_in_op(&self, attribute_map_id: u8, in_op_idx: u8) -> Result<bool, i32> {
        let arg_key = ExecArgKey {
            rule_idx: self.rule_idx,
            in_idx: in_op_idx,
        };
        unsafe {bpf_printk!(b"%d %d %d ridx: %d iidx: %d", 0, 0,0, self.rule_idx, in_op_idx);}
        unsafe {
            let Some(user_args) = self.args_map.get(&arg_key) else {
                return Ok(false);
            };
            for arg in user_args {
                if arg[0] == 0 {
                    return Ok(false);
                }
                if self.args.get(arg).is_some() {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}
