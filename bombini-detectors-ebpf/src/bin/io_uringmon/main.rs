#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{btf_tracepoint, map},
    maps::{hash_map::HashMap, lpm_trie::LpmTrie, Array},
    programs::BtfTracePointContext,
};

use bombini_common::config::io_uringmon::Config;
use bombini_common::constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_IOURING};

use bombini_detectors_ebpf::vmlinux::io_kiocb;

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
};

#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

#[map]
static IOURINGMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

// Filter maps

#[map]
static IOURINGMON_FILTER_UID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static IOURINGMON_FILTER_EUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static IOURINGMON_FILTER_AUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static IOURINGMON_FILTER_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static IOURINGMON_FILTER_BINNAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static IOURINGMON_FILTER_BINPREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[btf_tracepoint(function = "io_uring_submit_req")]
pub fn io_uring_submit_req_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_IOURING, false, try_submit_req) as u32
}

fn try_submit_req(ctx: BtfTracePointContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = IOURINGMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::IOUring(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process

    unsafe {
        let req: *const io_kiocb = ctx.arg(0);
        event.opcode = (*req).opcode;
        event.flags = (*req).flags as u64;
    }
    if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &IOURINGMON_FILTER_UID_MAP,
            &IOURINGMON_FILTER_EUID_MAP,
            &IOURINGMON_FILTER_AUID_MAP,
            &IOURINGMON_FILTER_BINNAME_MAP,
            &IOURINGMON_FILTER_BINPATH_MAP,
            &IOURINGMON_FILTER_BINPREFIX_MAP,
        );
        let mut allow = process_filter.filter(config.filter_mask, proc);
        if config.deny_list {
            allow = !allow;
        }
        if allow {
            util::copy_proc(proc, &mut event.process);
            return Ok(0);
        }
        return Err(0);
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
