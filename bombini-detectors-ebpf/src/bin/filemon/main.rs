#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{array::Array, hash_map::HashMap, lpm_trie::LpmTrie},
    programs::LsmContext,
};

use bombini_common::config::filemon::Config;

use bombini_common::constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX};
use bombini_common::event::file::{
    HOOK_FILE_OPEN, HOOK_PATH_CHMOD, HOOK_PATH_CHOWN, HOOK_PATH_TRUNCATE, HOOK_PATH_UNLINK,
    HOOK_SB_MOUNT,
};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_FILE};
use bombini_detectors_ebpf::vmlinux::{dentry, file, fmode_t, kgid_t, kuid_t, path, qstr};

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
};

#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

#[map]
static FILEMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

// Filter maps

// It's better to use BPF_MAP_TYPE_ARRAY_OF_MAPS when https://github.com/aya-rs/aya/pull/70
// will be merged. We can have array of maps to set separate process filters for hooks
#[map]
static FILEMON_FILTER_UID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_EUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_AUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINNAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINPREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

const FMODE_EXEC: u32 = 1 << 5;

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_open)
}

fn try_open(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_FILE_OPEN;
    unsafe {
        let fp: *const file = ctx.arg(0);
        let fmode: fmode_t = (*fp).f_mode;
        // Do not check opened files for execution. We have procmon for this
        if fmode & FMODE_EXEC != 0 {
            return Err(0);
        }
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read_kernel::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read_kernel::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "path_truncate")]
pub fn path_truncate_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_truncate)
}

fn try_truncate(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_PATH_TRUNCATE;
    unsafe {
        let p: *const path = ctx.arg(0);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "path_unlink")]
pub fn path_unlink_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_unlink)
}

fn try_unlink(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_PATH_UNLINK;
    unsafe {
        let p: *const path = ctx.arg(0);
        let entry: *const dentry = ctx.arg(1);
        let d_name =
            bpf_probe_read_kernel::<qstr>(&(*entry).d_name as *const _).map_err(|_| 0i32)?;
        aya_ebpf::memset(event.name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "path_chmod")]
pub fn path_chmod_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_chmod)
}

fn try_chmod(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_PATH_CHMOD;
    unsafe {
        let p: *const path = ctx.arg(0);
        event.i_mode = ctx.arg(1);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "path_chown")]
pub fn path_chown_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_chown)
}

fn try_chown(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_PATH_CHOWN;
    unsafe {
        let p: *const path = ctx.arg(0);
        event.uid = ctx.arg(1);
        event.gid = ctx.arg(2);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "sb_mount")]
pub fn sb_mount_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_sb_mount)
}

fn try_sb_mount(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
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

    event.hook = HOOK_SB_MOUNT;
    unsafe {
        let dev: *const u8 = ctx.arg(0);
        let mnt: *const path = ctx.arg(1);
        aya_ebpf::memset(event.name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(dev, &mut event.name).map_err(|_| 0i32)?;
        let _ = bpf_d_path(
            mnt as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
        event.flags = ctx.arg(2);
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
