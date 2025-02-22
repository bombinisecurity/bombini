#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, uretprobe},
    maps::lpm_trie::{Key, LpmTrie},
    programs::retprobe::RetProbeContext,
};

use bombini_common::event::histfile::MAX_BASH_COMMAND_SIZE;
use bombini_common::event::{Event, MSG_HISTFILE};
use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init};

#[map]
static HIST_CHECK_MAP: LpmTrie<[u8; MAX_BASH_COMMAND_SIZE], u32> = LpmTrie::with_max_entries(2, 0);

#[uretprobe]
pub fn histfile_detect(ctx: RetProbeContext) -> i32 {
    event_capture!(ctx, MSG_HISTFILE, try_detect, true) as i32
}

fn try_detect(ctx: RetProbeContext, event: &mut Event, _expose: bool) -> Result<u32, u32> {
    let Event::HistFile(event) = event else {
        return Err(0);
    };
    let command: *const u8 = ctx.ret().ok_or(0u32)?;
    unsafe {
        aya_ebpf::memset(event.command.as_mut_ptr(), 0, MAX_BASH_COMMAND_SIZE);
        bpf_probe_read_user_str_bytes(command, &mut event.command).map_err(|e| e as u32)?;
    }
    let lookup = Key::new((MAX_BASH_COMMAND_SIZE * 8) as u32, event.command);
    if HIST_CHECK_MAP.get(&lookup).is_some() {
        Ok(0)
    } else {
        Err(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
