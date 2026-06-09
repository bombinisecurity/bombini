#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_ANY, bpf_dynptr},
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
        r#gen::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::{btf_tracepoint, lsm, map},
    maps::{
        array::Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
    programs::{BtfTracePointContext, LsmContext},
};

use bombini_common::config::sysenummon::SysEnumMonKernelConfig;
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, PAGE_SIZE};
use bombini_common::event::process::{ProcInfo, ProcessKey};
use bombini_common::event::sysenum::{
    ChainItem, ChainItemNumber, ChainItemType, SYSENUMMON_CHAIN_MAX, SysEnumMsg,
};
use bombini_common::event::{Event, GenericEvent, MSG_SYSENUM};
use bombini_detectors_ebpf::co_re::{self, core_read_kernel};
use bombini_detectors_ebpf::{event_capture, util};

/// Kernel-side config.
#[map]
static SYSENUMMON_CONFIG: Array<SysEnumMonKernelConfig> = Array::with_max_entries(1, 0);

/// Shared ProcMon snapshot: pid -> ProcInfo.
#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

/// Per-parent (ppid) correlation state.
#[map]
static SYSENUMMON_STATE: LruHashMap<u32, SysEnumMsg> = LruHashMap::with_max_entries(128, 0);

/// Watched basename -> watch id.
#[map]
static SYSENUMMON_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> = HashMap::with_max_entries(1, 0);

/// Watched full path -> watch id.
#[map]
static SYSENUMMON_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> = HashMap::with_max_entries(1, 0);

/// Watched path prefix -> watch id.
#[map]
static SYSENUMMON_PATH_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

/// Per-CPU scratch for the resolved file path.
#[map]
static SYSENUMMON_PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU key buffer for the basename lookup.
#[map]
static SYSENUMMON_NAME_KEY_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

/// Per-CPU key buffer for the exact-path lookup.
#[map]
static SYSENUMMON_PATH_KEY_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> =
    PerCpuArray::with_max_entries(1, 0);

/// Per-CPU key buffer for the LPM prefix lookup.
#[map]
static SYSENUMMON_PREFIX_KEY_HEAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

/// Per-CPU zeroed template for new SYSENUMMON_STATE entries.
#[map]
static SYSENUMMON_STATE_HEAP: PerCpuArray<SysEnumMsg> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch to build one chain item before copying it into the state.
#[map]
static SYSENUMMON_ITEM_HEAP: PerCpuArray<ChainItem> = PerCpuArray::with_max_entries(1, 0);

/// Page of zeros copied by memzero instead of a memset.
#[map]
static ZERO_MAP: Array<[u8; PAGE_SIZE]> = Array::with_max_entries(1, 0);

macro_rules! memzero {
    ($mut_ptr:expr, $size:expr) => {{
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_MAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        bpf_dynptr_from_mem(
            $mut_ptr as *mut u8 as *mut _,
            $size as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(&tmp as *const _, 0, zero_ptr as *mut _, $size as u32, 0);
        let __very_dirty_verifier_hack = 0u8;
        core::hint::black_box(__very_dirty_verifier_hack);
    }};
}

#[lsm(hook = "bprm_check_security")]
pub fn sysmon_bprm_check(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_bprm_check)
}

#[lsm(hook = "file_open")]
pub fn sysmon_file_open(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SYSENUM, true, try_file_open)
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sysmon_process_exit(_ctx: BtfTracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    if pid == tgid {
        let _ = SYSENUMMON_STATE.remove(&tgid);
    }
    0
}

fn try_bprm_check(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::SysEnum(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let name_ptr = SYSENUMMON_NAME_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let name = unsafe { name_ptr.as_mut() }.ok_or(-1i32)?;

    unsafe {
        let binprm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let d_name = core_read_kernel!(binprm, file, f_path, dentry, d_name, name).ok_or(-1i32)?;
        memzero!(name.as_mut_ptr(), MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name, name).map_err(|_| -1i32)?;
    }

    let watch_id = unsafe { SYSENUMMON_NAME_MAP.get(name) }
        .copied()
        .ok_or(0i32)?;
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ppid = unsafe { PROCMON_PROC_MAP.get(&current_pid) }
        .ok_or(0i32)?
        .ppid;

    let item_ptr = SYSENUMMON_ITEM_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let item = unsafe { &mut *item_ptr };
    unsafe {
        *(&mut item.entry as *mut ChainItemType as *mut u8) = ChainItemNumber::Exec as u8;
    }
    let ChainItemType::Exec(ref mut binary) = item.entry else {
        return Err(-1);
    };
    unsafe {
        let _ = bpf_probe_read_kernel_buf(name.as_ptr(), binary);
    }
    record_hit(event, ppid, generic_event.ktime, watch_id)
}

fn try_file_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::SysEnum(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let path_ptr = SYSENUMMON_PATH_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let path = unsafe { path_ptr.as_mut() }.ok_or(-1i32)?;

    let path_key_ptr = SYSENUMMON_PATH_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let path_key = unsafe { path_key_ptr.as_mut() }.ok_or(-1i32)?;

    let prefix_key_ptr = SYSENUMMON_PREFIX_KEY_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let prefix_key = unsafe { prefix_key_ptr.as_mut() }.ok_or(-1i32)?;
    prefix_key.prefix_len = (MAX_FILE_PREFIX * 8) as u32;

    unsafe {
        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        memzero!(path.as_mut_ptr(), MAX_FILE_PATH);
        memzero!(path_key.as_mut_ptr(), MAX_FILE_PATH);
        memzero!(prefix_key.data.as_mut_ptr(), MAX_FILE_PREFIX);
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path.as_mut_ptr() as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path.as_ptr(), path_key).map_err(|_| -1i32)?;
        let _ = bpf_probe_read_kernel_buf(path.as_ptr(), &mut prefix_key.data);
    }

    let watch_id = unsafe { SYSENUMMON_PATH_MAP.get(path_key) }
        .or_else(|| SYSENUMMON_PATH_PREFIX_MAP.get(prefix_key))
        .copied()
        .ok_or(0i32)?;

    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ppid = unsafe { PROCMON_PROC_MAP.get(&current_pid) }
        .ok_or(0i32)?
        .ppid;

    let item_ptr = SYSENUMMON_ITEM_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let item = unsafe { &mut *item_ptr };
    unsafe {
        *(&mut item.entry as *mut ChainItemType as *mut u8) = ChainItemNumber::FileOpen as u8;
    }
    let ChainItemType::FileOpen(ref mut path) = item.entry else {
        return Err(-1);
    };
    unsafe {
        let _ = bpf_probe_read_kernel_buf(prefix_key.data.as_ptr(), path);
    }
    record_hit(event, ppid, generic_event.ktime, watch_id)
}

#[inline(always)]
fn record_hit(event: &mut SysEnumMsg, ppid: u32, now: u64, watch_id: u8) -> Result<i32, i32> {
    let config_ptr = SYSENUMMON_CONFIG.get_ptr(0).ok_or(-1i32)?;
    let config = unsafe { config_ptr.as_ref() }.ok_or(-1i32)?;
    let chain_size = config.chain_size;
    let window_ns = config.window_ns;
    if chain_size == 0 {
        return Err(0);
    }

    let Some(parent) = (unsafe { PROCMON_PROC_MAP.get(&ppid) }) else {
        return Err(0);
    };
    let mut process = ProcessKey { pid: 0, start: 0 };
    util::process_key_init(&mut process, parent);

    let state_ptr = if let Some(ptr) = SYSENUMMON_STATE.get_ptr_mut(&ppid) {
        ptr
    } else {
        let tmpl_ptr = SYSENUMMON_STATE_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
        unsafe { memzero!(tmpl_ptr, core::mem::size_of::<SysEnumMsg>()) };
        let tmpl = unsafe { &*tmpl_ptr };
        SYSENUMMON_STATE
            .insert(&ppid, tmpl, BPF_ANY as u64)
            .map_err(|x| x as i32)?;
        SYSENUMMON_STATE.get_ptr_mut(&ppid).ok_or(-1i32)?
    };
    let state = unsafe { &mut *state_ptr };

    let mut head = (state.head as usize) & SYSENUMMON_CHAIN_MAX;
    let mut len = (state.chain_len as usize) & SYSENUMMON_CHAIN_MAX;

    let mut expired = 0;
    while expired < len {
        let idx = (head + expired) & SYSENUMMON_CHAIN_MAX;
        if now.saturating_sub(state.chain[idx].timestamp_ns) <= window_ns {
            break;
        }
        expired += 1;
    }
    head = (head + expired) & SYSENUMMON_CHAIN_MAX;
    len = (len - expired) & SYSENUMMON_CHAIN_MAX;
    state.head = head as u8;
    state.chain_len = len as u8;

    // Skip if this watch id is already in the current chain.
    let mut i = 0;
    while i < len {
        let idx = (head + i) & SYSENUMMON_CHAIN_MAX;
        if state.watch_ids[idx] == watch_id {
            return Err(0);
        }
        i += 1;
    }

    if len >= SYSENUMMON_CHAIN_MAX {
        return Err(0);
    }

    let tail = (head + len) & SYSENUMMON_CHAIN_MAX;
    state.process = process;
    state.watch_ids[tail] = watch_id;

    let item_ptr = SYSENUMMON_ITEM_HEAP.get_ptr_mut(0).ok_or(-1i32)?;
    let item = unsafe { &mut *item_ptr };
    item.timestamp_ns = now;
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            &mut state.chain[tail] as *mut ChainItem as *mut u8,
            core::mem::size_of::<ChainItem>(),
        )
    };
    unsafe {
        let _ = bpf_probe_read_kernel_buf(item_ptr as *const u8, dst);
    }

    let new_len = (len + 1) as u8;
    state.chain_len = new_len;

    if new_len >= chain_size {
        let event_dst = unsafe {
            core::slice::from_raw_parts_mut(
                event as *mut SysEnumMsg as *mut u8,
                core::mem::size_of::<SysEnumMsg>(),
            )
        };
        unsafe {
            let _ = bpf_probe_read_kernel_buf(state as *const SysEnumMsg as *const u8, event_dst);
        }
        // Drop the state after emitting.
        let _ = SYSENUMMON_STATE.remove(&ppid);
        return Ok(0);
    }

    Err(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
