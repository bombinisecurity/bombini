#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_ANY, bpf_dynptr},
    helpers::{
        bpf_d_path, bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_ima_inode_hash, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
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
    event_capture,
    event_map::rb_event_init,
    filter::{
        procmon::cred::{CapFilter, CapValue, CredFilter, UidFilter},
        scope::ScopeFilter,
    },
    interpreter::{self, rule::IsEmpty},
    util,
    vmlinux::{
        cgroup, cred, css_set, file, kernfs_node, kgid_t, kuid_t, linux_binprm, mm_struct, path,
        pid_t, qstr, task_struct,
    },
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
fn get_creds(proc: &mut ProcInfo, task: *const task_struct) -> Result<u32, u32> {
    unsafe {
        let cred = bpf_probe_read_kernel::<*const cred>(&(*task).cred as *const *const _)
            .map_err(|_| 0u32)?;
        let euid = bpf_probe_read_kernel::<kuid_t>(&(*cred).euid as *const _).map_err(|_| 0u32)?;
        let uid = bpf_probe_read_kernel::<kuid_t>(&(*cred).uid as *const _).map_err(|_| 0u32)?;
        let egid = bpf_probe_read_kernel::<kgid_t>(&(*cred).egid as *const _).map_err(|_| 0u32)?;
        let gid = bpf_probe_read_kernel::<kgid_t>(&(*cred).gid as *const _).map_err(|_| 0u32)?;
        proc.creds.cap_effective = Capabilities::from_bits_retain(
            bpf_probe_read_kernel::<u64>(&(*cred).cap_effective as *const _ as *const u64)
                .map_err(|_| 0u32)?,
        );
        proc.creds.cap_inheritable = Capabilities::from_bits_retain(
            bpf_probe_read_kernel::<u64>(&(*cred).cap_inheritable as *const _ as *const u64)
                .map_err(|_| 0u32)?,
        );
        proc.creds.cap_permitted = Capabilities::from_bits_retain(
            bpf_probe_read_kernel::<u64>(&(*cred).cap_permitted as *const _ as *const u64)
                .map_err(|_| 0u32)?,
        );
        proc.creds.uid = uid.val;
        proc.creds.euid = euid.val;
        proc.creds.gid = gid.val;
        proc.creds.egid = egid.val;
    }
    Ok(0)
}

#[inline(always)]
fn is_cap_gained(new: u64, old: u64) -> bool {
    (new & !old) != 0
}

#[inline(always)]
fn get_cgroup_info(cgroup: &mut Cgroup, task: *const task_struct) -> Result<u32, u32> {
    unsafe {
        let cgroups = bpf_probe_read_kernel::<*mut css_set>(&(*task).cgroups as *const *mut _)
            .map_err(|_| 0u32)?;
        let cgrp = bpf_probe_read_kernel::<*mut cgroup>(&(*cgroups).dfl_cgrp as *const *mut _)
            .map_err(|_| 0u32)?;
        let kn = bpf_probe_read_kernel::<*mut kernfs_node>(&(*cgrp).kn as *const *mut _)
            .map_err(|_| 0u32)?;
        let name =
            bpf_probe_read_kernel::<*const _>(&(*kn).name as *const *const _).map_err(|_| 0u32)?;

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
    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };
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
            if let Ok(parent) =
                bpf_probe_read_kernel::<*mut task_struct>(&(*task).parent as *const _)
                    .map_err(|_| 0u32)
            {
                proc.ppid = bpf_probe_read_kernel(&(*parent).tgid as *const pid_t)
                    .map_err(|_| 0u32)? as u32;
            }
        }
    }

    // We need to read real executable name and get arguments from stack.
    let (arg_start, arg_end) = unsafe {
        proc.pid = pid;
        proc.tid = pid_tgid as u32;

        let mm = bpf_probe_read_kernel::<*mut mm_struct>(&(*task).mm as *const *mut _)
            .map_err(|_| 0u32)?;
        let mut arg_start =
            bpf_probe_read_kernel::<u64>(&(*mm).__bindgen_anon_1.arg_start as *const _)
                .map_err(|_| 0u32)?;

        let arg_end = bpf_probe_read_kernel::<u64>(&(*mm).__bindgen_anon_1.arg_end as *const _)
            .map_err(|_| 0u32)?;

        // Skip argv[0]
        let first_arg = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut proc.args)
            .map_err(|_| 0u32)?;

        arg_start += 1 + first_arg.len() as u64;

        let file =
            bpf_probe_read_kernel::<*mut file>(&(*mm).__bindgen_anon_1.exe_file as *const *mut _)
                .map_err(|_| 0u32)?;
        let path = bpf_probe_read_kernel::<path>(&(*file).f_path as *const _).map_err(|_| 0u32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0u32)?;

        memzero!(proc.filename.as_mut_ptr(), proc.filename.len());
        bpf_probe_read_kernel_str_bytes(d_name.name, &mut proc.filename).map_err(|_| 0u32)?;

        // Get cred
        get_creds(proc, task)?;

        // Get cgroups info (docker_id)
        get_cgroup_info(&mut proc.cgroup, task)?;

        let loginuid =
            bpf_probe_read_kernel::<kuid_t>(&(*task).loginuid as *const _).map_err(|_| 0u32)?;

        proc.auid = loginuid.val;

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
        let binprm: *const linux_binprm = ctx.arg(0);

        // if per_clear is zero, it's not a privileged execution
        if (*binprm).per_clear != 0 {
            // Get cred
            let cred = (*binprm).cred;
            let euid = bpf_probe_read_kernel::<kuid_t>(&(*cred).euid as *const _)
                .map_err(|_| 0i32)?
                .val;
            let uid = bpf_probe_read_kernel::<kuid_t>(&(*cred).uid as *const _)
                .map_err(|_| 0i32)?
                .val;
            let egid = bpf_probe_read_kernel::<kgid_t>(&(*cred).egid as *const _)
                .map_err(|_| 0i32)?
                .val;
            let gid = bpf_probe_read_kernel::<kgid_t>(&(*cred).gid as *const _)
                .map_err(|_| 0i32)?
                .val;
            if euid != uid {
                creds_info.secureexec |= SecureExec::SETUID;
            }
            if egid != gid {
                creds_info.secureexec |= SecureExec::SETGID;
            }
            let new_cap_p =
                bpf_probe_read_kernel::<u64>(&(*cred).cap_permitted as *const _ as *const u64)
                    .map_err(|_| 0i32)?;
            let task = bpf_get_current_task_btf() as *const task_struct;
            let task_cred = bpf_probe_read_kernel::<*const cred>(&(*task).cred as *const *const _)
                .map_err(|_| 0i32)?;
            let old_cap_p =
                bpf_probe_read_kernel::<u64>(&(*task_cred).cap_permitted as *const _ as *const u64)
                    .map_err(|_| 0i32)?;

            if is_cap_gained(new_cap_p, old_cap_p) && euid == uid {
                creds_info.secureexec |= SecureExec::FILE_CAPS;
            }
        }

        // Read full binary path here, because bpf_d_path can be used with only LSM/Fentry programs.
        let file: *mut file = (*binprm).file;
        let _ = bpf_d_path(
            &(*file).f_path as *const _ as *mut aya_ebpf::bindings::path,
            creds_info.binary_path.as_mut_ptr() as *mut _,
            creds_info.binary_path.len() as u32,
        );
        let inode = (*file).f_inode;
        let nlink = bpf_probe_read_kernel::<u32>(&(*inode).__bindgen_anon_1.__i_nlink as *const _)
            .map_err(|_| 0i32)?;
        if nlink == 0 {
            // It means that file was deleted or memfd_create was used for fileless exec
            creds_info.secureexec |= SecureExec::FILELESS_EXEC;
        }
        if config.ima_hash {
            creds_info.ima_hash.algo = bpf_ima_inode_hash(
                inode as *mut aya_ebpf::bindings::inode,
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
    let task: *const task_struct = unsafe { ctx.arg(1) };
    let tgid =
        unsafe { bpf_probe_read_kernel(&(*task).tgid as *const pid_t).map_err(|_| 0u32)? as u32 };
    let pid = unsafe {
        bpf_probe_read_kernel::<pid_t>(&(*task).pid as *const _).map_err(|_| 0u32)? as u32
    };

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
fn execve_find_parent(task: *const task_struct) -> Option<*const ProcInfo> {
    let mut parent = task;
    for _i in 0..4 {
        unsafe {
            let Ok(task) =
                bpf_probe_read_kernel::<*mut task_struct>(&(*parent).real_parent as *const _)
            else {
                return None;
            };
            parent = task;
            let Ok(pid) = bpf_probe_read_kernel(&(*parent).tgid as *const pid_t) else {
                return None;
            };
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
        let creds: *const cred = ctx.arg(0);
        event.flags = LsmSetIdFlags::from_bits_truncate(ctx.arg(2));
        event.uid = (*creds).uid.val;
        event.euid = (*creds).euid.val;
        event.fsuid = (*creds).fsuid.val;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        let mut proc_uid = UIDKey {
            rule_idx: 0,
            uid: event.uid,
        };

        let mut proc_euid = UIDKey {
            rule_idx: 0,
            uid: event.euid,
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
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(UidFilter::new(
                    &PROCMON_SETUID_UID_MAP,
                    &PROCMON_SETUID_EUID_MAP,
                    &proc_uid,
                    &proc_euid,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    enrich_with_proc_info(msg, proc);
                    return Ok(0);
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
        let creds: *const cred = ctx.arg(0);
        event.flags = LsmSetIdFlags::from_bits_truncate(ctx.arg(2));
        event.gid = (*creds).gid.val;
        event.egid = (*creds).egid.val;
        event.fsgid = (*creds).fsgid.val;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        let mut proc_gid = UIDKey {
            rule_idx: 0,
            uid: event.gid,
        };

        let mut proc_egid = UIDKey {
            rule_idx: 0,
            uid: event.egid,
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
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(UidFilter::new(
                    &PROCMON_SETGID_GID_MAP,
                    &PROCMON_SETGID_EGID_MAP,
                    &proc_gid,
                    &proc_egid,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    enrich_with_proc_info(msg, proc);
                    return Ok(0);
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
        let creds: *const cred = ctx.arg(0);
        event.effective =
            Capabilities::from_bits_retain(*(&(*creds).cap_effective as *const _ as *const u64));
        event.inheritable =
            Capabilities::from_bits_retain(*(&(*creds).cap_inheritable as *const _ as *const u64));
        event.permitted =
            Capabilities::from_bits_retain(*(&(*creds).cap_permitted as *const _ as *const u64));

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

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
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(CapFilter::new(
                    &PROCMON_CAPSET_ECAP_MAP,
                    &PROCMON_CAPSET_PCAP_MAP,
                    &proc_ecap,
                    &proc_pcap,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    enrich_with_proc_info(msg, proc);
                    return Ok(0);
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
            enrich_with_proc_info(msg, proc);
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
                enrich_with_proc_info(msg, proc);
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
            util::process_key_init(&mut msg.process, proc);
            return Ok(0);
        };

        let creds: *const cred = ctx.arg(0);
        let effective =
            Capabilities::from_bits_retain(*(&(*creds).cap_effective as *const _ as *const u64));
        let euid = (*creds).euid.val;

        let mut proc_ecap = CapValue {
            rule_idx: 0,
            caps: effective,
        };
        let mut proc_euid = UIDKey {
            rule_idx: 0,
            uid: euid,
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
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(CredFilter::new(
                    &PROCMON_USERNS_ECAP_MAP,
                    &PROCMON_USERNS_EUID_MAP,
                    &proc_ecap,
                    &proc_euid,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    util::process_key_init(&mut msg.process, proc);
                    return Ok(0);
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
        let child: *const task_struct = ctx.arg(0);
        event.mode = PtraceMode::from_bits_truncate(ctx.arg(1));
        let pid_child =
            bpf_probe_read_kernel::<pid_t>(&(*child).pid as *const _).map_err(|_| 0i32)? as u32;
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
fn enrich_with_proc_info(msg: &mut ProcessMsg, proc: &ProcInfo) {
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
