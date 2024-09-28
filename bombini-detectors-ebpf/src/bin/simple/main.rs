#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::kprobe,
    programs::ProbeContext,
};

use bombini_common::event::{Event, MSG_SIMPLE};
use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init};

#[kprobe]
pub fn simple(ctx: ProbeContext) -> u32 {
    event_capture!(ctx, MSG_SIMPLE, try_simple)
}

fn try_simple(_ctx: ProbeContext, event: &mut Event) -> Result<u32, u32> {
    let Event::Simple(event) = event else {
        return Err(0);
    };

    event.uid = bpf_get_current_uid_gid() as u32;
    event.pid = bpf_get_current_pid_tgid() as u32;
    if event.pid % 9 == 0 {
        Ok(0)
    } else {
        Err(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
