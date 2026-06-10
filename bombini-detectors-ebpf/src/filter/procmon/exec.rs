//! Credentials filters for bprm check

use aya_ebpf::maps::{HashMap, PerCpuHashMap};
use bombini_common::{
    config::rule::ExecArgKey,
    constants::{MAX_ARG_SIZE, MAX_ARGS_COUNT},
};

use crate::interpreter::CheckIn;

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
    fn check_in_op(&self, attribute_map_id: u8, _in_op_idx: u8) -> Result<bool, i32> {
        let arg_key = ExecArgKey {
            rule_idx: self.rule_idx,
            // Hack: we use attribute map id as in operation index.
            in_idx: attribute_map_id,
        };
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
