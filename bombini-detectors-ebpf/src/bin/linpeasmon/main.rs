#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_ANY,
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        array::Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};

use bombini_common::config::linpeasmon::{
    LINPEASMON_FULLNAME_SIZE, LinPEASMonKernelConfig, LinPEASMonState,
};
use bombini_common::config::rule::PathPrefixMapKey;
use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use bombini_common::event::linpeas::{LinPEASAlertKind, LinPEASCategory};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, GenericEvent, MSG_LINPEAS};
use bombini_detectors_ebpf::co_re::{self, core_read_kernel};

use bombini_detectors_ebpf::{event_capture, util};

#[map]
static LINPEASMON_CONFIG: Array<LinPEASMonKernelConfig> = Array::with_max_entries(1, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static LINPEASMON_STATE: LruHashMap<u32, LinPEASMonState> = LruHashMap::with_max_entries(4096, 0);

#[map]
static LINPEASMON_SIG_NAMES: HashMap<[u8; LINPEASMON_FULLNAME_SIZE], u8> =
    HashMap::with_max_entries(256, 0);

#[map]
static LINPEASMON_SIG_PREFIXES: LpmTrie<PathPrefixMapKey, u8> = LpmTrie::with_max_entries(256, 0);

#[map]
static LINPEASMON_FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static LINPEASMON_FULLNAME_HEAP: PerCpuArray<[u8; LINPEASMON_FULLNAME_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static LINPEASMON_PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static LINPEASMON_PREFIX_HEAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_LINPEAS, true, try_bprm_check)
}

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_LINPEAS, true, try_file_open)
}

fn try_bprm_check(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::LinPEAS(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let Some(config_ptr) = LINPEASMON_CONFIG.get_ptr(0) else {
        return Err(-1);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(-1);
    };
    if !config.behavioral_enabled {
        return Err(0);
    }

    let Some(filename_ptr) = LINPEASMON_FILENAME_HEAP.get_ptr_mut(0) else {
        return Err(-1);
    };
    let filename = unsafe { filename_ptr.as_mut() };
    let Some(filename) = filename else {
        return Err(-1);
    };
    filename.fill(0);

    let ppid = unsafe {
        let binprm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let d_name = core_read_kernel!(binprm, file, f_path, dentry, d_name, name).ok_or(-1i32)?;
        bpf_probe_read_kernel_str_bytes(d_name, filename).map_err(|_| -1i32)?;

        let task = co_re::task_struct::current();
        let parent_task = core_read_kernel!(task, parent).ok_or(-1i32)?;
        core_read_kernel!(parent_task, tgid).ok_or(-1i32)? as u32
    };

    let Some(category) = classify_filename(filename) else {
        return Err(0);
    };

    let parent_proc = unsafe { PROCMON_PROC_MAP.get(&ppid) };
    let Some(parent_proc) = parent_proc else {
        return Err(-1);
    };

    let now = generic_event.ktime;
    let mut state = match unsafe { LINPEASMON_STATE.get(&ppid) } {
        Some(s) => *s,
        None => LinPEASMonState {
            mask: 0,
            last_seen_ns: [0; 8],
        },
    };

    let mut i: usize = 0;
    while i < 8 {
        let bit_i = 1u8 << i;
        if state.mask & bit_i != 0 && now.saturating_sub(state.last_seen_ns[i]) > config.window_ns {
            state.mask &= !bit_i;
        }
        i += 1;
    }

    let idx = category as usize;
    let bit = 1u8 << idx;
    let was_set = state.mask & bit != 0;
    state.mask |= bit;
    state.last_seen_ns[idx] = now;
    let _ = LINPEASMON_STATE.insert(&ppid, &state, BPF_ANY as u64);

    if was_set {
        return Err(0);
    }

    let count = state.mask.count_ones() as u8;
    if count < config.threshold {
        return Err(0);
    }

    util::process_key_init(&mut event.process, parent_proc);
    if let Some(grandparent) = unsafe { PROCMON_PROC_MAP.get(&parent_proc.ppid) } {
        util::process_key_init(&mut event.parent, grandparent);
    }
    event.kind = LinPEASAlertKind::Behavioral as u8;
    event.mask = state.mask;
    event.category_count = count;
    Ok(0)
}

fn try_file_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::LinPEAS(ref mut event) = generic_event.event else {
        return Err(-1);
    };

    let Some(config_ptr) = LINPEASMON_CONFIG.get_ptr(0) else {
        return Err(-1);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(-1);
    };
    if !config.signature_enabled {
        return Err(0);
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(path_ptr) = LINPEASMON_PATH_HEAP.get_ptr_mut(0) else {
        return Err(-1);
    };
    let Some(prefix_ptr) = LINPEASMON_PREFIX_HEAP.get_ptr_mut(0) else {
        return Err(-1);
    };
    let Some(filename_ptr) = LINPEASMON_FULLNAME_HEAP.get_ptr_mut(0) else {
        return Err(-1);
    };

    let mut hit = false;

    unsafe {
        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );

        let prefix = prefix_ptr.as_mut().ok_or(-1i32)?;
        prefix.data.rule_idx = 0;
        bpf_probe_read_kernel_buf(path_ptr as *const u8, &mut prefix.data.path_prefix)
            .map_err(|_| 0_i32)?;
        prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
        if LINPEASMON_SIG_PREFIXES.get(&*prefix).is_some() {
            hit = true;
        }

        if !hit {
            let d_name = core_read_kernel!(fp, f_path, dentry, d_name, name).ok_or(-1i32)?;
            let name = filename_ptr.as_mut().ok_or(-1i32)?;
            name.fill(0);
            bpf_probe_read_kernel_str_bytes(d_name, name).map_err(|_| -1i32)?;
            if LINPEASMON_SIG_NAMES.get(name).is_some() {
                hit = true;
            }
        }
    }

    if !hit {
        return Err(0);
    }

    util::process_key_init(&mut event.process, proc);
    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(&proc.ppid) } {
        util::process_key_init(&mut event.parent, parent);
    }
    event.kind = LinPEASAlertKind::Signature as u8;
    event.mask = 0;
    event.category_count = 0;
    Ok(0)
}

#[inline(always)]
fn classify_filename(filename: &[u8; MAX_FILENAME_SIZE]) -> Option<LinPEASCategory> {
    let len = first_zero(filename);
    let name = &filename[..len];
    if name == b"id" || name == b"whoami" || name == b"groups" {
        return Some(LinPEASCategory::SuidSgid);
    }
    if name == b"sudo" {
        return Some(LinPEASCategory::SudoCheck);
    }
    if name == b"getcap" || name == b"capsh" {
        return Some(LinPEASCategory::Capabilities);
    }
    if name == b"find" || name == b"stat" || name == b"ls" {
        return Some(LinPEASCategory::SensitiveFiles);
    }
    if name == b"ps" || name == b"pgrep" || name == b"pidof" || name == b"top" {
        return Some(LinPEASCategory::ProcessEnum);
    }
    if name == b"uname"
        || name == b"hostname"
        || name == b"lsmod"
        || name == b"dmesg"
        || name == b"sysctl"
    {
        return Some(LinPEASCategory::KernelInfo);
    }
    if name == b"docker"
        || name == b"podman"
        || name == b"runc"
        || name == b"kubectl"
        || name == b"crictl"
    {
        return Some(LinPEASCategory::ContainerInfo);
    }
    if name == b"ip"
        || name == b"ifconfig"
        || name == b"netstat"
        || name == b"ss"
        || name == b"route"
        || name == b"arp"
        || name == b"iptables"
    {
        return Some(LinPEASCategory::NetworkInfo);
    }
    None
}

#[inline(always)]
fn first_zero(buf: &[u8; MAX_FILENAME_SIZE]) -> usize {
    let mut i = 0;
    while i < MAX_FILENAME_SIZE {
        if buf[i] == 0 {
            return i;
        }
        i += 1;
    }
    MAX_FILENAME_SIZE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
