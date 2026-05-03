#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_ANY, bpf_dynptr},
    helpers::{
        bpf_d_path, bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ima_inode_hash,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
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

use bombini_common::{
    config::procmon::ProcMonKernelConfig,
    config::rule::{CapKey, FileNameMapKey, PathMapKey, PathPrefixMapKey, Rules, UIDKey},
    constants::{
        MAX_ARGS_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE, MAX_IMA_HASH_SIZE,
        PAGE_SIZE,
    },
    event::{
        Event, GenericEvent, MSG_PROCESS, MSG_PROCESS_CLONE, MSG_PROCESS_EXEC, MSG_PROCESS_EXIT,
        process::{
            Capabilities, Cgroup, ImaHash, LsmSetIdFlags, PR_SET_DUMPABLE, PR_SET_KEEPCAPS,
            PR_SET_NAME, PR_SET_SECUREBITS, PrctlCmd, ProcInfo, ProcessEventNumber,
            ProcessEventVariant, ProcessMsg, PtraceMode, SecureExec,
        },
    },
};

use bombini_detectors_ebpf::{
    co_re::{self, core_read_kernel},
    event_capture,
    filter::{
        filemon::path::PathFilter,
        procmon::cred::{CapFilter, CapValue, CredFilter, UidFilter},
        scope::ScopeFilter,
    },
    interpreter::{self, rule::IsEmpty},
    util,
};

/// Extra info from bprm_committing_creds hook
struct CredSharedInfo {
    pub secureexec: SecureExec,
    /// full binary path
    pub binary_path: [u8; MAX_FILE_PATH],
    /// IMA hash for binary
    pub ima_hash: ImaHash,
}

/// Holds current live processes
#[map]
pub static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

/// Holds process information gathered on bprm_commiting_creds
#[map]
static PROCMON_CRED_SHARED_MAP: LruHashMap<u64, CredSharedInfo> = LruHashMap::pinned(8192, 0);

#[map]
static PROCMON_CRED_HEAP: PerCpuArray<CredSharedInfo> = PerCpuArray::with_max_entries(1, 0);

// Detector config
#[map]
static PROCMON_CONFIG: Array<ProcMonKernelConfig> = Array::with_max_entries(1, 0);

// Helpers
#[map]
static PROCMON_HEAP: PerCpuArray<ProcInfo> = PerCpuArray::with_max_entries(1, 0);

#[map]
static ZERO_MAP: Array<[u8; PAGE_SIZE]> = Array::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

/// Fill file name map
macro_rules! fill_name_map {
    ($map:ident, $src:expr) => {{
        let Some(name_ptr) = $map.get_ptr_mut(0) else {
            return Err(0);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(0);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        bpf_dynptr_from_mem(
            &mut name.name as *mut u8 as *mut _,
            MAX_FILENAME_SIZE as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(
            &tmp as *const _,
            0,
            zero_ptr as *mut _,
            MAX_FILENAME_SIZE as u32,
            0,
        );
        bpf_probe_read_kernel_str_bytes($src as *const u8, &mut name.name).map_err(|_| 0i32)?;
        name
    }};
}

/// Fill file path map
macro_rules! fill_path_map {
    ($map:ident, $src:expr) => {{
        let Some(path_ptr) = $map.get_ptr_mut(0) else {
            return Err(0);
        };
        let path = path_ptr.as_mut();
        let Some(path) = path else {
            return Err(0);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        bpf_dynptr_from_mem(
            &mut path.path as *mut u8 as *mut _,
            MAX_FILE_PATH as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(
            &tmp as *const _,
            0,
            zero_ptr as *mut _,
            MAX_FILE_PATH as u32,
            0,
        );
        bpf_probe_read_kernel_str_bytes($src as *const u8, &mut path.path).map_err(|_| 0i32)?;
        path
    }};
}

macro_rules! fill_prefix_map {
    ($map:ident, $src:expr) => {{
        let Some(prefix) = $map.get_ptr_mut(0) else {
            return Err(0);
        };
        let prefix = prefix.as_mut();
        let Some(prefix) = prefix else {
            return Err(0);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        bpf_dynptr_from_mem(
            prefix.data.path_prefix.as_mut_ptr() as *mut u8 as *mut _,
            core::mem::size_of_val(&prefix.data.path_prefix) as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(
            &tmp as *const _,
            0,
            zero_ptr as *mut _,
            core::mem::size_of_val(&prefix.data.path_prefix) as u32,
            0,
        );
        bpf_probe_read_kernel_buf($src as *const u8, &mut prefix.data.path_prefix)
            .map_err(|_| 0)?;
        prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
        prefix
    }};
}

#[map]
static DYNPTR_HELPER: PerCpuArray<bpf_dynptr> = PerCpuArray::with_max_entries(1, 0);

macro_rules! memzero {
    ($mut_ptr:expr, $size:expr) => {{
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        bpf_dynptr_from_mem(
            $mut_ptr as *mut u8 as *mut _,
            $size as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(&tmp as *const _, 0, zero_ptr as *mut _, $size as u32, 0);
    }
    // <VERIFIER_ISSUE>
    // Very dirty hack to make BPF verifier happy with stack area used for dynptr.
    // After dynptr is passed away from the scope, BPF verifier still thinks that stack area is untouchable.
    // We can create new variable that will may separate this stack area from the dynptr.
    let __very_dirty_verifier_hack = 0u8;
    core::hint::black_box(__very_dirty_verifier_hack);};
}

// Attribute helper maps
#[map]
static PROCMON_BINARY_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_BINARY_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_BINARY_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn get_creds(proc: &mut ProcInfo, task: co_re::task_struct) -> Result<u32, u32> {
    unsafe {
        let cred = core_read_kernel!(task, cred).ok_or(0u32)?;
        proc.creds.uid = cred.uid();
        proc.creds.euid = cred.euid();
        proc.creds.gid = cred.gid();
        proc.creds.egid = cred.egid();
        proc.creds.cap_effective = Capabilities::from_bits_retain(cred.cap_effective());
        proc.creds.cap_inheritable = Capabilities::from_bits_retain(cred.cap_inheritable());
        proc.creds.cap_permitted = Capabilities::from_bits_retain(cred.cap_permitted());
    }
    Ok(0)
}

#[inline(always)]
fn is_cap_gained(new: u64, old: u64) -> bool {
    (new & !old) != 0
}

#[inline(always)]
fn get_cgroup_info(cgroup: &mut Cgroup, task: co_re::task_struct) -> Result<u32, u32> {
    unsafe {
        let name = core_read_kernel!(task, cgroups, dfl_cgrp, kn, name).ok_or(0u32)?;
        memzero!(cgroup.cgroup_name.as_mut_ptr(), cgroup.cgroup_name.len());
        bpf_probe_read_kernel_str_bytes(name as *const _, &mut cgroup.cgroup_name)
            .map_err(|_| 0u32)?;
        cgroup.cgroup_id = bpf_get_current_cgroup_id();
    }
    Ok(0)
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn execve_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_PROCESS_EXEC, true, try_execve)
}

fn try_execve(_ctx: BtfTracePointContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let ktime = generic_event.ktime;
    let Event::ProcessExec((ref mut event_proc, ref mut event_parent)) = generic_event.event else {
        return Err(0);
    };
    let task = unsafe { co_re::task_struct::current() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let Some(proc_ptr) = PROCMON_PROC_MAP.get_ptr_mut(&pid) else {
        return Err(0);
    };
    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };
    proc.prev_start = proc.start;
    proc.start = ktime;
    let parent_proc = execve_find_parent(task);
    if let Some(parent_proc) = parent_proc {
        proc.ppid = unsafe { (*parent_proc).pid };
        event_parent.pid = proc.ppid;
        event_parent.start = unsafe { (*parent_proc).start };
    } else {
        unsafe {
            if let Some(parent) = core_read_kernel!(task, parent)
                && let Some(tgid) = core_read_kernel!(parent, tgid)
            {
                proc.ppid = tgid as u32;
            }
        }
    }

    // We need to read real executable name and get arguments from stack.
    let (arg_start, arg_end) = unsafe {
        proc.pid = pid;
        proc.tid = pid_tgid as u32;

        let mm_core = core_read_kernel!(task, mm).ok_or(0u32)?;
        let mut arg_start = core_read_kernel!(mm_core, arg_start).ok_or(0u32)?;
        let arg_end = core_read_kernel!(mm_core, arg_end).ok_or(0u32)?;

        // Skip argv[0]
        let first_arg = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut proc.args)
            .map_err(|_| 0u32)?;

        arg_start += 1 + first_arg.len() as u64;

        let file = core_read_kernel!(mm_core, exe_file).ok_or(0u32)?;
        let d_name = core_read_kernel!(file, f_path, dentry, d_name, name).ok_or(0u32)?;

        memzero!(proc.filename.as_mut_ptr(), proc.filename.len());
        bpf_probe_read_kernel_str_bytes(d_name, &mut proc.filename).map_err(|_| 0u32)?;

        // Get cred
        get_creds(proc, task)?;

        // Get cgroups info (docker_id)
        get_cgroup_info(&mut proc.cgroup, task)?;

        let loginuid = task.loginuid().unwrap_or(u32::MAX);
        proc.auid = loginuid;

        (arg_start, arg_end)
    };
    let arg_size = (arg_end - arg_start) & (MAX_ARGS_SIZE - 1) as u64;
    unsafe {
        memzero!(proc.args.as_mut_ptr(), proc.args.len());
        bpf_probe_read_user_buf(arg_start as *const u8, &mut proc.args[..arg_size as usize])
            .map_err(|_| 0u32)?;
    }

    if let Some(cred_info) = PROCMON_CRED_SHARED_MAP.get_ptr(&pid_tgid) {
        unsafe {
            let Some(cred_info) = cred_info.as_ref() else {
                return Err(0);
            };
            proc.creds.secureexec = cred_info.secureexec;
            memzero!(proc.binary_path.as_mut_ptr(), proc.binary_path.len());
            bpf_probe_read_kernel_str_bytes(cred_info.binary_path.as_ptr(), &mut proc.binary_path)
                .map_err(|_| 0u32)?;
            if cred_info.ima_hash.algo > 0 {
                proc.ima_hash.algo = cred_info.ima_hash.algo;
                bpf_probe_read_kernel_buf(
                    cred_info.ima_hash.hash.as_ptr(),
                    &mut proc.ima_hash.hash,
                )
                .map_err(|_| 0u32)?;
            }
        }
        PROCMON_CRED_SHARED_MAP.remove(&pid_tgid).unwrap();
    }

    proc.cloned = false;
    util::copy_proc(proc, event_proc);
    Ok(0)
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn exit_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_PROCESS_EXIT, true, try_exit)
}

fn try_exit(_ctx: BtfTracePointContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let Event::ProcessExit((ref mut event_proc, ref mut event_parent)) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(proc_ptr) = PROCMON_PROC_MAP.get_ptr_mut(&pid) else {
        return Err(0);
    };
    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };

    if let Some(parent_proc) = PROCMON_PROC_MAP.get_ptr(&proc.ppid) {
        unsafe {
            event_parent.pid = (*parent_proc).pid;
            event_parent.start = (*parent_proc).start;
        }
    }

    // Mark exited for garbage collector
    proc.exited = true;
    util::process_key_init(event_proc, proc);
    Ok(0)
}

#[lsm(hook = "bprm_committing_creds", sleepable)]
pub fn creds_capture(ctx: LsmContext) -> i32 {
    let _ = try_committing_creds(ctx);
    0
}

fn try_committing_creds(ctx: LsmContext) -> Result<i32, i32> {
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(cred_ptr) = PROCMON_CRED_HEAP.get_ptr_mut(0) else {
        return Err(0);
    };

    let creds_info = unsafe { cred_ptr.as_mut() };

    let Some(creds_info) = creds_info else {
        return Err(0);
    };
    creds_info.ima_hash.algo = 0;
    unsafe {
        memzero!(cred_ptr, core::mem::size_of_val(creds_info));
        let binprm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let per_clear = core_read_kernel!(binprm, per_clear).unwrap_or(0);

        // if per_clear is zero, it's not a privileged execution
        if per_clear != 0 {
            // Get cred
            let cred = core_read_kernel!(binprm, cred).ok_or(0i32)?;
            let euid = cred.euid();
            let uid = cred.uid();
            let egid = cred.egid();
            let gid = cred.gid();
            if euid != uid {
                creds_info.secureexec |= SecureExec::SETUID;
            }
            if egid != gid {
                creds_info.secureexec |= SecureExec::SETGID;
            }
            let new_cap_p = cred.cap_permitted();
            let task_core = co_re::task_struct::current();
            let task_cred_core = core_read_kernel!(task_core, cred).ok_or(0i32)?;
            let old_cap_p = task_cred_core.cap_permitted();

            if is_cap_gained(new_cap_p, old_cap_p) && euid == uid {
                creds_info.secureexec |= SecureExec::FILE_CAPS;
            }
        }

        // Read full binary path here, because bpf_d_path can be used with only LSM/Fentry programs.
        let file = core_read_kernel!(binprm, file).ok_or(0i32)?;
        let f_path = core_read_kernel!(file, f_path).ok_or(0i32)?;
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            creds_info.binary_path.as_mut_ptr() as *mut _,
            creds_info.binary_path.len() as u32,
        );
        let inode = core_read_kernel!(file, f_inode).ok_or(0i32)?;
        let nlink = inode.__i_nlink().ok_or(0i32)?;
        if nlink == 0 {
            // It means that file was deleted or memfd_create was used for fileless exec
            creds_info.secureexec |= SecureExec::FILELESS_EXEC;
        }
        if config.ima_hash {
            creds_info.ima_hash.algo = bpf_ima_inode_hash(
                inode.as_ptr() as *mut aya_ebpf::bindings::inode,
                creds_info.ima_hash.hash.as_mut_ptr() as *mut _,
                MAX_IMA_HASH_SIZE as u32,
            ) as i8;
        }
        let _ = PROCMON_CRED_SHARED_MAP.insert(&pid_tgid, creds_info, BPF_ANY as u64);
    }
    Ok(0)
}

#[btf_tracepoint(function = "sched_process_fork")]
pub fn fork_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_PROCESS_CLONE, false, try_fork)
}

fn try_fork(ctx: BtfTracePointContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let task = unsafe { co_re::task_struct::from_ptr(ctx.arg(1)) };
    let tgid = unsafe { core_read_kernel!(task, tgid).ok_or(0u32)? as u32 };
    let pid = unsafe { core_read_kernel!(task, pid).ok_or(0u32)? as u32 };

    // Do not track threads
    if pid != tgid {
        return Err(0);
    }

    let parent_proc = execve_find_parent(task);
    let Some(parent_proc) = parent_proc else {
        return Err(0);
    };
    let proc_ptr = exec_map_get_init(tgid)?;
    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };
    proc.start = generic_event.ktime;
    proc.pid = tgid;
    unsafe {
        proc.ppid = (*parent_proc).pid;
        proc.tid = pid;
        bpf_probe_read_kernel_str_bytes(&(*parent_proc).filename as *const _, &mut proc.filename)
            .map_err(|_| 0u32)?;
        bpf_probe_read_kernel_str_bytes(
            &(*parent_proc).binary_path as *const _,
            &mut proc.binary_path,
        )
        .map_err(|_| 0u32)?;
        bpf_probe_read_kernel_buf(&(*parent_proc).args as *const _, &mut proc.args)
            .map_err(|_| 0u32)?;
        get_creds(proc, task)?;
    }
    proc.cloned = true;
    let Event::ProcessClone((ref mut event_proc, ref mut event_parent)) = generic_event.event
    else {
        return Err(0);
    };
    unsafe {
        event_parent.pid = (*parent_proc).pid;
        event_parent.start = (*parent_proc).start;
    }
    util::copy_proc(proc, event_proc);
    Ok(0)
}

#[inline(always)]
fn execve_find_parent(task: co_re::task_struct) -> Option<*const ProcInfo> {
    let mut parent = task;
    for _i in 0..4 {
        unsafe {
            let task = core_read_kernel!(parent, real_parent)?;
            parent = task;
            let pid = core_read_kernel!(parent, tgid)?;
            if let Some(proc_ptr) = PROCMON_PROC_MAP.get_ptr(&(pid as u32)) {
                return Some(proc_ptr);
            }
        }
    }
    None
}

#[inline(always)]
fn exec_map_get_init(pid: u32) -> Result<*mut ProcInfo, u32> {
    if let Some(proc_ptr) = PROCMON_PROC_MAP.get_ptr_mut(&pid) {
        return Ok(proc_ptr);
    }

    let proc_ptr = PROCMON_HEAP.get_ptr_mut(0).ok_or(0u32)?;

    let proc = unsafe { proc_ptr.as_mut() };

    let proc = proc.ok_or(0u32)?;
    unsafe {
        memzero!(proc_ptr, core::mem::size_of_val(proc));
    }
    PROCMON_PROC_MAP
        .insert(&pid, proc, BPF_ANY as u64)
        .map_err(|x| x as u32)?;
    PROCMON_PROC_MAP.get_ptr_mut(&pid).ok_or(0)
}

// Setuid rules map
#[map]
static PROCMON_SETUID_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter setuid maps begin
#[map]
static PROCMON_SETUID_UID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETUID_EUID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETUID_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETUID_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETUID_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "task_fix_setuid")]
pub fn setuid_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_setuid_capture)
}

fn try_setuid_capture(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_SETUID_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::Setuid as u8;
    }
    let ProcessEventVariant::Setuid(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let creds = co_re::cred::from_ptr(ctx.arg(0));
        event.flags = LsmSetIdFlags::from_bits_truncate(ctx.arg(2));
        event.uid = creds.uid();
        event.euid = creds.euid();
        event.fsuid = creds.fsuid();

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[ProcessEventNumber::Setuid as usize];

        let mut proc_uid = UIDKey {
            rule_idx: 0,
            value: event.uid,
        };

        let mut proc_euid = UIDKey {
            rule_idx: 0,
            value: event.euid,
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            proc_uid.rule_idx = idx as u32;
            proc_euid.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_SETUID_BINNAME_MAP,
                &PROCMON_SETUID_BINPATH_MAP,
                &PROCMON_SETUID_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            // <VERIFIER_ISSUE>
            // Without blackbox, the verifier will complain that the program is too huge.
            let scope_passed = scope_filter.check_predicate(&rule.scope)?;
            if core::hint::black_box(scope_passed) {
                let mut event_filter = interpreter::Interpreter::new(UidFilter::new(
                    &PROCMON_SETUID_UID_MAP,
                    &PROCMON_SETUID_EUID_MAP,
                    &proc_uid,
                    &proc_euid,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            }
        }
    }
    Err(0)
}

// Setgid rules map
#[map]
static PROCMON_SETGID_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter setgid maps begin
#[map]
static PROCMON_SETGID_GID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETGID_EGID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETGID_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETGID_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_SETGID_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "task_fix_setgid")]
pub fn setgid_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_setgid_capture)
}

fn try_setgid_capture(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_SETGID_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::Setgid as u8;
    }
    let ProcessEventVariant::Setgid(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let creds = co_re::cred::from_ptr(ctx.arg(0));
        event.flags = LsmSetIdFlags::from_bits_truncate(ctx.arg(2));
        event.gid = creds.gid();
        event.egid = creds.egid();
        event.fsgid = creds.fsgid();

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[ProcessEventNumber::Setgid as usize];

        let mut proc_gid = UIDKey {
            rule_idx: 0,
            value: event.gid,
        };

        let mut proc_egid = UIDKey {
            rule_idx: 0,
            value: event.egid,
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            proc_gid.rule_idx = idx as u32;
            proc_egid.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_SETGID_BINNAME_MAP,
                &PROCMON_SETGID_BINPATH_MAP,
                &PROCMON_SETGID_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            // <VERIFIER_ISSUE>
            // Without blackbox, the verifier will complain that the program is too huge.
            let scope_passed = scope_filter.check_predicate(&rule.scope)?;
            if core::hint::black_box(scope_passed) {
                let mut event_filter = interpreter::Interpreter::new(UidFilter::new(
                    &PROCMON_SETGID_GID_MAP,
                    &PROCMON_SETGID_EGID_MAP,
                    &proc_gid,
                    &proc_egid,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            }
        }
    }

    Err(0)
}

// Capset rules map
#[map]
static PROCMON_CAPSET_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter capset maps begin
#[map]
static PROCMON_CAPSET_ECAP_MAP: HashMap<CapKey, Capabilities> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_CAPSET_PCAP_MAP: HashMap<CapKey, Capabilities> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_CAPSET_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_CAPSET_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_CAPSET_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "capset")]
pub fn capset_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_capset_capture)
}

fn try_capset_capture(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_CAPSET_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::Setcaps as u8;
    }
    let ProcessEventVariant::Setcaps(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let creds = co_re::cred::from_ptr(ctx.arg(0));
        event.effective = Capabilities::from_bits_retain(creds.cap_effective());
        event.inheritable = Capabilities::from_bits_retain(creds.cap_inheritable());
        event.permitted = Capabilities::from_bits_retain(creds.cap_permitted());

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[ProcessEventNumber::Setcaps as usize];

        let mut proc_ecap = CapValue {
            rule_idx: 0,
            caps: event.effective,
        };

        let mut proc_pcap = CapValue {
            rule_idx: 0,
            caps: event.permitted,
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            proc_ecap.rule_idx = idx as u8;
            proc_pcap.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_CAPSET_BINNAME_MAP,
                &PROCMON_CAPSET_BINPATH_MAP,
                &PROCMON_CAPSET_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            // <VERIFIER_ISSUE>
            // Without blackbox, the verifier will complain that the program is too huge.
            let scope_passed = scope_filter.check_predicate(&rule.scope)?;
            if core::hint::black_box(scope_passed) {
                let mut event_filter = interpreter::Interpreter::new(CapFilter::new(
                    &PROCMON_CAPSET_ECAP_MAP,
                    &PROCMON_CAPSET_PCAP_MAP,
                    &proc_ecap,
                    &proc_pcap,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            }
        }
    }

    Err(0)
}

// Prctl rules map
#[map]
static PROCMON_PRCTL_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter prctl maps begin
#[map]
static PROCMON_PRCTL_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_PRCTL_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_PRCTL_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> = LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "task_prctl")]
pub fn prctl_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_prctl_capture)
}

fn try_prctl_capture(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_PRCTL_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::Prctl as u8;
    }
    let ProcessEventVariant::Prctl(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let cmd: u8 = ctx.arg(0);
        match cmd {
            PR_SET_DUMPABLE => event.cmd = PrctlCmd::PrSetDumpable(ctx.arg::<u8>(1)),
            PR_SET_KEEPCAPS => event.cmd = PrctlCmd::PrSetKeepCaps(ctx.arg::<u8>(1)),
            PR_SET_SECUREBITS => event.cmd = PrctlCmd::PrSetSecurebits(ctx.arg::<u32>(1)),
            PR_SET_NAME => {
                let name_ptr: *const u8 = ctx.arg(1);
                let mut name: [u8; 16] = [0; 16];
                bpf_probe_read_user_str_bytes(name_ptr, &mut name).map_err(|_| 0i32)?;
                event.cmd = PrctlCmd::PrSetName { name };
            }
            _ => event.cmd = PrctlCmd::Opcode(cmd),
        }

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_PRCTL_BINNAME_MAP,
                &PROCMON_PRCTL_BINPATH_MAP,
                &PROCMON_PRCTL_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                return Ok(0);
            }
        }
    }

    Err(0)
}

// Userns rules map
#[map]
static PROCMON_USERNS_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter userns maps begin
#[map]
static PROCMON_USERNS_ECAP_MAP: HashMap<CapKey, Capabilities> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_USERNS_EUID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_USERNS_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_USERNS_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_USERNS_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "create_user_ns")]
pub fn create_user_ns_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_create_user_ns_capture)
}

fn try_create_user_ns_capture(
    ctx: LsmContext,
    generic_event: &mut GenericEvent,
) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_USERNS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::CreateUserNs as u8;
    }
    let ProcessEventVariant::CreateUserNs = msg.event else {
        return Err(0);
    };

    unsafe {
        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[ProcessEventNumber::CreateUserNs as usize];

        let creds = co_re::cred::from_ptr(ctx.arg(0));
        let effective = Capabilities::from_bits_retain(creds.cap_effective());
        let euid = creds.euid();

        let mut proc_ecap = CapValue {
            rule_idx: 0,
            caps: effective,
        };
        let mut proc_euid = UIDKey {
            rule_idx: 0,
            value: euid,
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            proc_ecap.rule_idx = idx as u8;
            proc_euid.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_USERNS_BINNAME_MAP,
                &PROCMON_USERNS_BINPATH_MAP,
                &PROCMON_USERNS_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            // <VERIFIER_ISSUE>
            // Without blackbox, the verifier will complain that the program is too huge.
            let scope_passed = scope_filter.check_predicate(&rule.scope)?;
            if core::hint::black_box(scope_passed) {
                let mut event_filter = interpreter::Interpreter::new(CredFilter::new(
                    &PROCMON_USERNS_ECAP_MAP,
                    &PROCMON_USERNS_EUID_MAP,
                    &proc_ecap,
                    &proc_euid,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            }
        }
    }
    Err(0)
}

// Ptrace access check rules map
#[map]
static PROCMON_PTRACE_ACCESS_CHECK_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter ptrace access check maps begin
#[map]
static PROCMON_PTRACE_ACCESS_CHECK_BINPATH_MAP: HashMap<PathMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_PTRACE_ACCESS_CHECK_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_PTRACE_ACCESS_CHECK_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_ptrace_access_check_capture)
}

fn try_ptrace_access_check_capture(
    ctx: LsmContext,
    generic_event: &mut GenericEvent,
) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_PTRACE_ACCESS_CHECK_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::PtraceAccessCheck as u8;
    }

    unsafe {
        let Some(ref rule_array) = rules.0 else {
            return enrich_ptrace_access_check_info(msg, proc, &ctx);
        };

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_PTRACE_ACCESS_CHECK_BINNAME_MAP,
                &PROCMON_PTRACE_ACCESS_CHECK_BINPATH_MAP,
                &PROCMON_PTRACE_ACCESS_CHECK_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                return enrich_ptrace_access_check_info(msg, proc, &ctx);
            }
        }
    }
    Err(0)
}

// Bprm_check rules map
#[map]
static PROCMON_BPRM_CHECK_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter bprm_check maps begin
#[map]
static PROCMON_BPRM_CHECK_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_BPRM_CHECK_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_BPRM_CHECK_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static PROCMON_BPRM_CHECK_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_BPRM_CHECK_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_BPRM_CHECK_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "bprm_check")]
pub fn bprm_check_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PROCESS, true, try_bprm_check_capture)
}

fn try_bprm_check_capture(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Process(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = PROCMON_BPRM_CHECK_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut ProcessEventVariant as *mut u8;
        *p = ProcessEventNumber::BprmCheck as u8;
    }
    let ProcessEventVariant::BprmCheck(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let binrpm = co_re::linux_binprm::from_ptr(ctx.arg(0));
        let file = core_read_kernel!(binrpm, file).ok_or(0i32)?;
        let f_path = core_read_kernel!(file, f_path).ok_or(0i32)?;

        // Get full path
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };

        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.binary)
            .map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[ProcessEventNumber::BprmCheck as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(file, f_path, dentry, d_name, name).ok_or(0i32)?;
        let file_name = fill_name_map!(PROCMON_FILE_NAME_MAP, d_name);

        // Get file path
        let file_path = fill_path_map!(PROCMON_PATH_MAP, &event.binary);

        // Get file prefix
        let file_prefix = fill_prefix_map!(PROCMON_PATH_PREFIX_MAP, &event.binary);

        // Get binary name
        let binary_name = fill_name_map!(PROCMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(PROCMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(PROCMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &PROCMON_BPRM_CHECK_BINNAME_MAP,
                &PROCMON_BPRM_CHECK_BINPATH_MAP,
                &PROCMON_BPRM_CHECK_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            // <VERIFIER_ISSUE>
            // Without blackbox, the verifier will complain that the program is too huge.
            let scope_passed = scope_filter.check_predicate(&rule.scope)?;
            if core::hint::black_box(scope_passed) {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &PROCMON_BPRM_CHECK_NAME_MAP,
                    &PROCMON_BPRM_CHECK_PATH_MAP,
                    &PROCMON_BPRM_CHECK_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            }
        }
    }
    Err(0)
}

#[inline(always)]
fn enrich_ptrace_access_check_info(
    msg: &mut ProcessMsg,
    proc: &ProcInfo,
    ctx: &LsmContext,
) -> Result<i32, i32> {
    let ProcessEventVariant::PtraceAccessCheck(ref mut event) = msg.event else {
        return Err(0);
    };

    let proc_child = unsafe {
        let child = co_re::task_struct::from_ptr(ctx.arg(0));
        event.mode = PtraceMode::from_bits_truncate(ctx.arg(1));
        let pid_child = core_read_kernel!(child, pid).ok_or(0i32)? as u32;
        PROCMON_PROC_MAP.get(&pid_child)
    };
    let Some(proc_child) = proc_child else {
        return Err(0);
    };

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(&proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    util::copy_proc(proc_child, &mut event.child);
    Ok(0)
}

#[inline(always)]
fn enrich_with_proc_info_and_rule_idx(msg: &mut ProcessMsg, proc: &ProcInfo, rule_idx: Option<u8>) {
    msg.rule_idx = rule_idx;

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(&proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
