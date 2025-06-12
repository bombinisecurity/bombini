#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_tracepoint, map},
    maps::hash_map::HashMap,
    programs::BtfTracePointContext,
};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_IOURING};

use bombini_detectors_ebpf::vmlinux::io_kiocb;

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

#[btf_tracepoint(function = "io_uring_submit_req")]
pub fn io_uring_submit_req_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_IOURING, false, try_submit_req) as u32
}

fn try_submit_req(ctx: BtfTracePointContext, event: &mut Event) -> Result<i32, i32> {
    let Event::IOUring(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    unsafe {
        let req: *const io_kiocb = ctx.arg(0);
        event.opcode = (*req).opcode;
        event.flags = (*req).flags;
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
