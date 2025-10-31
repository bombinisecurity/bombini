#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, uretprobe},
    maps::{
        hash_map::LruHashMap,
        lpm_trie::{Key, LpmTrie},
    },
    programs::retprobe::RetProbeContext,
};

use bombini_common::event::histfile::MAX_BASH_COMMAND_SIZE;
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, GenericEvent, MSG_HISTFILE};
use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static HISTFILE_CHECK_MAP: LpmTrie<[u8; MAX_BASH_COMMAND_SIZE], u32> =
    LpmTrie::with_max_entries(2, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[uretprobe]
pub fn histfile_detect(ctx: RetProbeContext) -> i32 {
    event_capture!(ctx, MSG_HISTFILE, true, try_detect)
}

fn try_detect(ctx: RetProbeContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::HistFile(ref mut event) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
    let command: *const u8 = ctx.ret().ok_or(0i32)?;
    unsafe {
        bpf_probe_read_user_str_bytes(command, &mut event.command).map_err(|_| 0i32)?;
    }
    let lookup = Key::new((MAX_BASH_COMMAND_SIZE * 8) as u32, event.command);
    if HISTFILE_CHECK_MAP.get(&lookup).is_some() {
        // Copy process info to Rb
        util::copy_proc(proc, &mut event.process);
        Ok(0)
    } else {
        Err(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
