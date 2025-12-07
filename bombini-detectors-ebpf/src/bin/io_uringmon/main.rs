#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_buf,
    },
    macros::{btf_tracepoint, map},
    maps::{
        Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::LpmTrie,
    },
    programs::BtfTracePointContext,
};

use bombini_common::config::io_uringmon::Config;
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use bombini_common::event::io_uring::IOUringOp;
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, GenericEvent, MSG_IOURING};

use bombini_detectors_ebpf::vmlinux::{file, filename, io_kiocb, open_how, sockaddr};

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
};

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

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

fn try_submit_req(ctx: BtfTracePointContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = IOURINGMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::IOUring(ref mut event) = generic_event.event else {
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
        event.opcode = core::mem::transmute::<u8, IOUringOp>((*req).opcode);
        match event.opcode {
            IOUringOp::IORING_OP_OPENAT | IOUringOp::IORING_OP_OPENAT2 => {
                let open_data = bpf_probe_read_kernel::<io_open>(
                    &(*req).__bindgen_anon_1.cmd as *const _ as *const _,
                )
                .map_err(|_| 0i32)?;
                let filename_data =
                    bpf_probe_read_kernel::<filename>(open_data.filename as *const _)
                        .map_err(|_| 0i32)?;
                bpf_probe_read_kernel_str_bytes(filename_data.name as *const _, &mut event.path)
                    .map_err(|_| 0i32)?;
                event.flags = open_data.how.flags;
            }
            IOUringOp::IORING_OP_STATX => {
                let statx_data = bpf_probe_read_kernel::<io_statx>(
                    &(*req).__bindgen_anon_1.cmd as *const _ as *const _,
                )
                .map_err(|_| 0i32)?;
                let filename_data =
                    bpf_probe_read_kernel::<filename>(statx_data.filename as *const _)
                        .map_err(|_| 0i32)?;
                bpf_probe_read_kernel_str_bytes(filename_data.name as *const _, &mut event.path)
                    .map_err(|_| 0i32)?;
            }
            IOUringOp::IORING_OP_UNLINKAT => {
                let unlink_data = bpf_probe_read_kernel::<io_unlink>(
                    &(*req).__bindgen_anon_1.cmd as *const _ as *const _,
                )
                .map_err(|_| 0i32)?;
                let filename_data =
                    bpf_probe_read_kernel::<filename>(unlink_data.filename as *const _)
                        .map_err(|_| 0i32)?;
                bpf_probe_read_kernel_str_bytes(filename_data.name as *const _, &mut event.path)
                    .map_err(|_| 0i32)?;
            }
            IOUringOp::IORING_OP_CONNECT => {
                let connect_data = bpf_probe_read_kernel::<io_connect>(
                    &(*req).__bindgen_anon_1.cmd as *const _ as *const _,
                )
                .map_err(|_| 0i32)?;
                bpf_probe_read_user_buf(connect_data.addr as *const u8, &mut event.sockaddr)
                    .map_err(|_| 0i32)?;
            }
            IOUringOp::IORING_OP_ACCEPT => {
                let accept_data = bpf_probe_read_kernel::<io_accept>(
                    &(*req).__bindgen_anon_1.cmd as *const _ as *const _,
                )
                .map_err(|_| 0i32)?;
                bpf_probe_read_user_buf(accept_data.addr as *const u8, &mut event.sockaddr)
                    .map_err(|_| 0i32)?;
            }
            _ => {}
        }
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
            util::process_key_init(&mut event.process, proc);
            return Ok(0);
        }
        return Err(0);
    }
    util::process_key_init(&mut event.process, proc);
    Ok(0)
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct io_open {
    pub file: *mut file,
    pub dfd: i32,
    pub file_slot: u32,
    pub filename: *mut filename,
    pub how: open_how,
    pub nofile: u32,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct io_statx {
    pub file: *mut file,
    pub dfd: i32,
    pub mask: u32,
    pub flags: u32,
    pub filename: *mut filename,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct io_connect {
    pub file: *mut file,
    pub addr: *mut sockaddr,
    pub addr_len: i32,
    pub in_progress: bool,
    pub seen_econnaborted: bool,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct io_unlink {
    pub file: *mut file,
    pub dfd: i32,
    pub flags: u32,
    pub filename: *mut filename,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct io_accept {
    pub file: *mut file,
    pub addr: *mut sockaddr,
    pub addr_len: *mut i32,
    pub flags: i32,
    pub iou_flags: i32,
    pub file_slot: u32,
    pub nofile: u32,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
