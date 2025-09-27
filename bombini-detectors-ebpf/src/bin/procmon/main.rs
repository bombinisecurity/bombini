#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_ANY,
    helpers::{
        bpf_d_path, bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_ima_inode_hash, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{btf_tracepoint, lsm, map},
    maps::{
        array::Array, hash_map::HashMap, hash_map::LruHashMap, lpm_trie::LpmTrie,
        per_cpu_array::PerCpuArray,
    },
    programs::{BtfTracePointContext, LsmContext},
};

use bombini_detectors_ebpf::vmlinux::{
    cgroup, cred, css_set, file, kernfs_node, kgid_t, kuid_t, linux_binprm, mm_struct, path, pid_t,
    qstr, task_struct,
};

use bombini_common::config::procmon::Config;
use bombini_common::constants::{
    MAX_ARGS_SIZE, MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_IMA_HASH_SIZE,
};
use bombini_common::event::process::{
    Capabilities, Cgroup, ImaHash, LsmSetUidFlags, PrctlCmd, ProcInfo, PtraceMode, SecureExec,
    PR_SET_DUMPABLE, PR_SET_KEEPCAPS, PR_SET_NAME, PR_SET_SECUREBITS,
};
use bombini_common::event::{
    Event, MSG_CAPSET, MSG_CREATE_USER_NS, MSG_PRCTL, MSG_PROCEXEC, MSG_PROCEXIT,
    MSG_PTRACE_ACCESS_CHECK, MSG_SETUID,
};

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
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
pub static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

/// Holds process information gathered on bprm_commiting_creds
#[map]
static PROCMON_CRED_SHARED_MAP: LruHashMap<u64, CredSharedInfo> = LruHashMap::pinned(8192, 0);

#[map]
static PROCMON_CRED_HEAP: PerCpuArray<CredSharedInfo> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_HEAP: PerCpuArray<ProcInfo> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

// Filter maps

#[map]
static PROCMON_FILTER_UID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_FILTER_EUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_FILTER_AUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_FILTER_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_FILTER_BINNAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static PROCMON_FILTER_BINPREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[inline(always)]
unsafe fn get_creds(proc: &mut ProcInfo, task: *const task_struct) -> Result<u32, u32> {
    let cred =
        bpf_probe_read_kernel::<*const cred>(&(*task).cred as *const *const _).map_err(|_| 0u32)?;
    let euid = bpf_probe_read_kernel::<kuid_t>(&(*cred).euid as *const _).map_err(|_| 0u32)?;
    let uid = bpf_probe_read_kernel::<kuid_t>(&(*cred).uid as *const _).map_err(|_| 0u32)?;
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
    Ok(0)
}

#[inline(always)]
fn is_cap_gained(new: u64, old: u64) -> bool {
    (new & !old) != 0
}

#[inline(always)]
unsafe fn get_cgroup_info(cgroup: &mut Cgroup, task: *const task_struct) -> Result<u32, u32> {
    let cgroups = bpf_probe_read_kernel::<*mut css_set>(&(*task).cgroups as *const *mut _)
        .map_err(|_| 0u32)?;
    let cgrp = bpf_probe_read_kernel::<*mut cgroup>(&(*cgroups).dfl_cgrp as *const *mut _)
        .map_err(|_| 0u32)?;
    let kn = bpf_probe_read_kernel::<*mut kernfs_node>(&(*cgrp).kn as *const *mut _)
        .map_err(|_| 0u32)?;
    let name =
        bpf_probe_read_kernel::<*const _>(&(*kn).name as *const *const _).map_err(|_| 0u32)?;

    aya_ebpf::memset(cgroup.cgroup_name.as_mut_ptr(), 0, cgroup.cgroup_name.len());
    bpf_probe_read_kernel_str_bytes(name as *const _, &mut cgroup.cgroup_name).map_err(|_| 0u32)?;
    cgroup.cgroup_id = bpf_get_current_cgroup_id();
    Ok(0)
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn execve_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_PROCEXEC, false, try_execve)
}

fn try_execve(_ctx: BtfTracePointContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::ProcExec(event) = event else {
        return Err(0);
    };
    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let proc_ptr = unsafe { exec_map_get_init(pid) };
    let Some(proc_ptr) = proc_ptr else {
        return Err(0);
    };
    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };
    let parent_proc = unsafe { execve_find_parent(task) };
    if let Some(parent_proc) = parent_proc {
        proc.ppid = unsafe { (*parent_proc).pid };
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
        aya_ebpf::memset(proc.args.as_mut_ptr(), 0, proc.args.len());
        bpf_probe_read_user_buf(arg_start as *const u8, &mut proc.args[..arg_size as usize])
            .map_err(|_| 0u32)?;
    }

    if let Some(cred_info) = PROCMON_CRED_SHARED_MAP.get_ptr(&pid_tgid) {
        unsafe {
            let Some(cred_info) = cred_info.as_ref() else {
                return Err(0);
            };
            proc.creds.secureexec = cred_info.secureexec.clone();
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

    proc.clonned = false;
    if config.expose_events {
        if !config.filter_mask.is_empty() {
            let process_filter: ProcessFilter = ProcessFilter::new(
                &PROCMON_FILTER_UID_MAP,
                &PROCMON_FILTER_EUID_MAP,
                &PROCMON_FILTER_AUID_MAP,
                &PROCMON_FILTER_BINNAME_MAP,
                &PROCMON_FILTER_BINPATH_MAP,
                &PROCMON_FILTER_BINPREFIX_MAP,
            );
            let mut allow = process_filter.filter(config.filter_mask, proc);
            if config.deny_list {
                allow = !allow;
            }
            if allow {
                util::copy_proc(proc, event);
                return Ok(0);
            }
            return Err(0);
        }
        util::copy_proc(proc, event);
        return Ok(0);
    }
    Err(0)
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn exit_capture(ctx: BtfTracePointContext) -> u32 {
    event_capture!(ctx, MSG_PROCEXIT, false, try_exit)
}

fn try_exit(_ctx: BtfTracePointContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::ProcExit(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
    if config.expose_events {
        if !config.filter_mask.is_empty() {
            let process_filter: ProcessFilter = ProcessFilter::new(
                &PROCMON_FILTER_UID_MAP,
                &PROCMON_FILTER_EUID_MAP,
                &PROCMON_FILTER_AUID_MAP,
                &PROCMON_FILTER_BINNAME_MAP,
                &PROCMON_FILTER_BINPATH_MAP,
                &PROCMON_FILTER_BINPREFIX_MAP,
            );
            let mut allow = process_filter.filter(config.filter_mask, proc);
            if config.deny_list {
                allow = !allow;
            }
            if allow {
                util::copy_proc(proc, event);
                PROCMON_PROC_MAP.remove(&pid).unwrap();
                return Ok(0);
            }
            PROCMON_PROC_MAP.remove(&pid).unwrap();
            return Err(0);
        }
        util::copy_proc(proc, event);
        PROCMON_PROC_MAP.remove(&pid).unwrap();
        return Ok(0);
    }
    PROCMON_PROC_MAP.remove(&pid).unwrap();
    Err(0)
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
        aya_ebpf::memset(cred_ptr as *mut u8, 0, core::mem::size_of_val(creds_info));
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
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(_ctx: BtfTracePointContext) -> Result<u32, u32> {
    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };
    let tgid =
        unsafe { bpf_probe_read_kernel(&(*task).tgid as *const pid_t).map_err(|_| 0u32)? as u32 };
    let pid = unsafe {
        bpf_probe_read_kernel::<pid_t>(&(*task).pid as *const _).map_err(|_| 0u32)? as u32
    };

    // Do not track threads
    if pid != tgid {
        return Err(0);
    }

    let parent_proc = unsafe { execve_find_parent(task) };
    let Some(parent_proc) = parent_proc else {
        return Err(0);
    };
    let proc_ptr = unsafe { exec_map_get_init(tgid) };
    let Some(proc_ptr) = proc_ptr else {
        return Err(0);
    };
    let proc = unsafe { proc_ptr.as_mut() };

    let Some(proc) = proc else {
        return Err(0);
    };
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
    proc.clonned = true;
    Ok(0)
}

#[inline(always)]
unsafe fn execve_find_parent(task: *const task_struct) -> Option<*const ProcInfo> {
    let mut parent = task;
    for _i in 0..4 {
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
    None
}

#[inline(always)]
unsafe fn exec_map_get_init(pid: u32) -> Option<*mut ProcInfo> {
    if let Some(proc_ptr) = PROCMON_PROC_MAP.get_ptr_mut(&pid) {
        return Some(proc_ptr);
    }

    let proc_ptr = PROCMON_HEAP.get_ptr_mut(0)?;

    let proc = unsafe { proc_ptr.as_mut() };

    let proc = proc?;
    aya_ebpf::memset(proc_ptr as *mut u8, 0, core::mem::size_of_val(proc));
    if PROCMON_PROC_MAP.insert(&pid, proc, BPF_ANY as u64).is_err() {
        return None;
    }
    PROCMON_PROC_MAP.get_ptr_mut(&pid)
}

// Privelage escalation hooks
#[inline(always)]
fn filter_by_process(config: &Config, proc: &ProcInfo) -> Result<(), i32> {
    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &PROCMON_FILTER_UID_MAP,
            &PROCMON_FILTER_EUID_MAP,
            &PROCMON_FILTER_AUID_MAP,
            &PROCMON_FILTER_BINNAME_MAP,
            &PROCMON_FILTER_BINPATH_MAP,
            &PROCMON_FILTER_BINPREFIX_MAP,
        );
        if config.deny_list {
            !process_filter.filter(config.filter_mask, proc)
        } else {
            process_filter.filter(config.filter_mask, proc)
        }
    } else {
        true
    };

    // Skip argument parsing if event is not exported
    if !allow {
        return Err(0);
    }

    Ok(())
}

#[lsm(hook = "task_fix_setuid")]
pub fn setuid_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_SETUID, false, try_setuid_capture)
}

fn try_setuid_capture(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::ProcSetUid(event) = event else {
        return Err(0);
    };
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let creds: *const cred = ctx.arg(0);
        event.flags = LsmSetUidFlags::from_bits_truncate(ctx.arg(2));
        event.uid = (*creds).uid.val;
        event.euid = (*creds).euid.val;
        event.fsuid = (*creds).fsuid.val;
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "capset")]
pub fn capset_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_CAPSET, false, try_capset_capture)
}

fn try_capset_capture(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::ProcCapset(event) = event else {
        return Err(0);
    };
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let creds: *const cred = ctx.arg(0);
        event.effective = Capabilities::from_bits_retain((*creds).cap_effective.val);
        event.inheritable = Capabilities::from_bits_retain((*creds).cap_inheritable.val);
        event.permitted = Capabilities::from_bits_retain((*creds).cap_permitted.val)
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "task_prctl")]
pub fn task_prctl_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_PRCTL, false, try_task_prctl_capture)
}

fn try_task_prctl_capture(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::ProcPrctl(event) = event else {
        return Err(0);
    };
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

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
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "create_user_ns")]
pub fn create_user_ns_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_CREATE_USER_NS, false, try_create_user_ns_capture)
}

fn try_create_user_ns_capture(_ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::ProcCreateUserNs(event) = event else {
        return Err(0);
    };
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check_capture(ctx: LsmContext) -> i32 {
    event_capture!(
        ctx,
        MSG_PTRACE_ACCESS_CHECK,
        false,
        try_ptrace_access_check_capture
    )
}

fn try_ptrace_access_check_capture(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Event::ProcPtraceAccessCheck(event) = event else {
        return Err(0);
    };
    let Some(config_ptr) = PROCMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

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
    util::copy_proc(proc, &mut event.process);
    util::copy_proc(proc_child, &mut event.child);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
