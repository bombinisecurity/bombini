#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        array::Array, hash_map::HashMap, lpm_trie::LpmTrie, per_cpu_array::PerCpuArray, LruHashMap,
    },
    programs::LsmContext,
};

use bombini_common::config::filemon::Config;

use bombini_common::constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX};
use bombini_common::event::file::{
    HOOK_FILE_IOCTL, HOOK_FILE_OPEN, HOOK_MMAP_FILE, HOOK_PATH_CHMOD, HOOK_PATH_CHOWN,
    HOOK_PATH_TRUNCATE, HOOK_PATH_UNLINK, HOOK_SB_MOUNT,
};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, MSG_FILE};
use bombini_detectors_ebpf::vmlinux::{dentry, file, kgid_t, kuid_t, path, qstr};

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::path::PathFilter,
    filter::process::ProcessFilter, util,
};

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static FILEMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

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

#[inline(always)]
fn filter_by_process(config: &Config, proc: &ProcInfo) -> Result<(), i32> {
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

    Ok(())
}

#[map]
static FILEMON_FILTER_OPEN_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_OPEN_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_OPEN_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_open)
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

    filter_by_process(config, proc)?;

    event.hook = HOOK_FILE_OPEN;
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let fp: *const file = ctx.arg(0);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;

        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read_kernel::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read_kernel::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
        // Filter event by path
        if !config.path_mask[0].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_OPEN_NAME_MAP,
                &FILEMON_FILTER_OPEN_PATH_MAP,
                &FILEMON_FILTER_OPEN_PREFIX_MAP,
            );
            let path =
                bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
            if !path_filter.filter(config.path_mask[0], &event.path, &event.name) {
                return Err(0);
            }
        }
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[map]
static FILEMON_FILTER_TRUNC_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_TRUNC_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_TRUNC_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

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

    filter_by_process(config, proc)?;

    event.hook = HOOK_PATH_TRUNCATE;
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let p: *const path = ctx.arg(0);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[1].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_TRUNC_NAME_MAP,
                &FILEMON_FILTER_TRUNC_PATH_MAP,
                &FILEMON_FILTER_TRUNC_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
            if !path_filter.filter(config.path_mask[1], &event.path, &event.name) {
                return Err(0);
            }
        }
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

    filter_by_process(config, proc)?;

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

#[map]
static FILEMON_FILTER_CHMOD_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_CHMOD_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_CHMOD_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

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

    filter_by_process(config, proc)?;

    event.hook = HOOK_PATH_CHMOD;
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let p: *const path = ctx.arg(0);
        event.i_mode = ctx.arg(1);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[3].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_CHMOD_NAME_MAP,
                &FILEMON_FILTER_CHMOD_PATH_MAP,
                &FILEMON_FILTER_CHMOD_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
            if !path_filter.filter(config.path_mask[3], &event.path, &event.name) {
                return Err(0);
            }
        }
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[map]
static FILEMON_FILTER_CHOWN_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_CHOWN_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_CHOWN_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

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

    filter_by_process(config, proc)?;

    event.hook = HOOK_PATH_CHOWN;
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let p: *const path = ctx.arg(0);
        event.uid = ctx.arg(1);
        event.gid = ctx.arg(2);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[4].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_CHOWN_NAME_MAP,
                &FILEMON_FILTER_CHOWN_PATH_MAP,
                &FILEMON_FILTER_CHOWN_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
            if !path_filter.filter(config.path_mask[4], &event.path, &event.name) {
                return Err(0);
            }
        }
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

    filter_by_process(config, proc)?;

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

#[map]
static FILEMON_FILTER_MMAP_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_MMAP_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_MMAP_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "mmap_file")]
pub fn mmap_file_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_mmap_file)
}

fn try_mmap_file(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
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

    filter_by_process(config, proc)?;

    event.hook = HOOK_MMAP_FILE;
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let fp: *const file = ctx.arg(0);
        event.prot = ctx.arg(1);
        event.flags = ctx.arg(2);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;

        // Filter event by path
        if !config.path_mask[6].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_MMAP_NAME_MAP,
                &FILEMON_FILTER_MMAP_PATH_MAP,
                &FILEMON_FILTER_MMAP_PREFIX_MAP,
            );
            let path =
                bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
            if !path_filter.filter(config.path_mask[6], &event.path, &event.name) {
                return Err(0);
            }
        }
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_file_ioctl)
}

fn try_file_ioctl(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
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

    filter_by_process(config, proc)?;

    event.hook = HOOK_FILE_IOCTL;
    unsafe {
        let fp: *const file = ctx.arg(0);
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.flags = ctx.arg(1);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
