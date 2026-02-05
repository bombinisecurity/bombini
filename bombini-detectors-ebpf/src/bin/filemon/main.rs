#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        LruHashMap, array::Array, hash_map::HashMap, lpm_trie::LpmTrie, per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};

use bombini_common::config::filemon::Config;

use bombini_common::constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE};
use bombini_common::event::file::{FileEventNumber, FileEventVariant};
use bombini_common::event::process::ProcInfo;
use bombini_common::event::{Event, GenericEvent, MSG_FILE};
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

#[map]
static FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> = PerCpuArray::with_max_entries(1, 0);

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

fn try_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::FileOpen as u8;
    }
    let FileEventVariant::FileOpen(ref mut event) = msg.event else {
        return Err(0);
    };
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
        if !config.path_mask[FileEventNumber::FileOpen as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_OPEN_NAME_MAP,
                &FILEMON_FILTER_OPEN_PATH_MAP,
                &FILEMON_FILTER_OPEN_PREFIX_MAP,
            );
            let path =
                bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;
            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::FileOpen as usize],
                &event.path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
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

fn try_truncate(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathTruncate as u8;
    }
    let FileEventVariant::PathTruncate(ref mut event) = msg.event else {
        return Err(0);
    };
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
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, event).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[FileEventNumber::PathTruncate as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_TRUNC_NAME_MAP,
                &FILEMON_FILTER_TRUNC_PATH_MAP,
                &FILEMON_FILTER_TRUNC_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::PathTruncate as usize],
                event,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    Ok(0)
}

#[map]
static FILEMON_FILTER_UNLINK_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_UNLINK_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_UNLINK_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "path_unlink")]
pub fn path_unlink_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_unlink)
}

fn try_unlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathUnlink as u8;
    }
    let FileEventVariant::PathUnlink(ref mut event) = msg.event else {
        return Err(0);
    };
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let p: *const path = ctx.arg(0);
        let len = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        let len = len as usize & (MAX_FILE_PATH - 1);
        if len == 0 || len as usize > MAX_FILE_PATH - MAX_FILENAME_SIZE - 1 {
            return Err(0);
        }
        let path_buf = path_ptr.as_mut();
        let Some(path_buf) = path_buf else {
            return Err(0);
        };
        path_buf[len as usize - 1] = b'/';
        let entry: *const dentry = ctx.arg(1);
        let d_name =
            bpf_probe_read_kernel::<qstr>(&(*entry).d_name as *const _).map_err(|_| 0i32)?;
        let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(0);
        };
        core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, event).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event[len as usize..])
            .map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[FileEventNumber::PathUnlink as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_UNLINK_NAME_MAP,
                &FILEMON_FILTER_UNLINK_PATH_MAP,
                &FILEMON_FILTER_UNLINK_PREFIX_MAP,
            );
            if !path_filter.filter(
                config.path_mask[FileEventNumber::PathUnlink as usize],
                event,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    Ok(0)
}

#[map]
static FILEMON_FILTER_SYMLINK_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_SYMLINK_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_SYMLINK_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "path_symlink")]
pub fn path_symlink_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_symlink)
}

fn try_symlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathSymlink as u8;
    }
    let FileEventVariant::PathSymlink(ref mut event) = msg.event else {
        return Err(0);
    };
    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let p: *const path = ctx.arg(0);
        let len = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        let len = len as usize & (MAX_FILE_PATH - 1);
        if len == 0 || len as usize > MAX_FILE_PATH - MAX_FILENAME_SIZE - 1 {
            return Err(0);
        }
        let path_buf = path_ptr.as_mut();
        let Some(path_buf) = path_buf else {
            return Err(0);
        };
        path_buf[len as usize - 1] = b'/';
        let entry: *const dentry = ctx.arg(1);
        let d_name =
            bpf_probe_read_kernel::<qstr>(&(*entry).d_name as *const _).map_err(|_| 0i32)?;
        let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(0);
        };
        core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.link_path)
            .map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event.link_path[len as usize..])
            .map_err(|_| 0i32)?;
        // Get old path
        bpf_probe_read_kernel_str_bytes(ctx.arg(2), &mut event.old_path).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[FileEventNumber::PathSymlink as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_SYMLINK_NAME_MAP,
                &FILEMON_FILTER_SYMLINK_PATH_MAP,
                &FILEMON_FILTER_SYMLINK_PREFIX_MAP,
            );
            // Find the last '/' in the path
            let Some(bsp) = event.old_path.iter().rposition(|x| x == &b'/') else {
                return Err(0);
            };
            // Get file name from the old path
            let (_, name_slice) = event.old_path.split_at(bsp);
            // skip the first slash byte
            let name_slice = &name_slice[1..];
            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);

            let copy_len = name_slice.len().min(MAX_FILENAME_SIZE);
            // Verifier issues
            if name_slice.len() < copy_len {
                return Err(0);
            }
            if name.len() < copy_len {
                return Err(0);
            }
            // Lengths must be equal
            name[..copy_len].copy_from_slice(&name_slice[..copy_len]);
            if !path_filter.filter(
                config.path_mask[FileEventNumber::PathSymlink as usize],
                &event.old_path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
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
    event_capture!(ctx, MSG_FILE, true, try_chmod)
}

fn try_chmod(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathChmod as u8;
    }
    let FileEventVariant::PathChmod(ref mut event) = msg.event else {
        return Err(0);
    };
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
        if !config.path_mask[FileEventNumber::PathChmod as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_CHMOD_NAME_MAP,
                &FILEMON_FILTER_CHMOD_PATH_MAP,
                &FILEMON_FILTER_CHMOD_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::PathChmod as usize],
                &event.path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
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
    event_capture!(ctx, MSG_FILE, true, try_chown)
}

fn try_chown(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathChown as u8;
    }
    let FileEventVariant::PathChown(ref mut event) = msg.event else {
        return Err(0);
    };
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
        if !config.path_mask[FileEventNumber::PathChown as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_CHOWN_NAME_MAP,
                &FILEMON_FILTER_CHOWN_PATH_MAP,
                &FILEMON_FILTER_CHOWN_PREFIX_MAP,
            );
            let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;

            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::PathChown as usize],
                &event.path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    Ok(0)
}

#[lsm(hook = "sb_mount")]
pub fn sb_mount_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_sb_mount)
}

fn try_sb_mount(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::SbMount as u8;
    }
    let FileEventVariant::SbMount(ref mut event) = msg.event else {
        return Err(0);
    };
    unsafe {
        let dev: *const u8 = ctx.arg(0);
        let mnt: *const path = ctx.arg(1);
        bpf_probe_read_kernel_str_bytes(dev, &mut event.name).map_err(|_| 0i32)?;
        let _ = bpf_d_path(
            mnt as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
        event.flags = ctx.arg(2);
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
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

fn try_mmap_file(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::MmapFile as u8;
    }
    let FileEventVariant::MmapFile(ref mut event) = msg.event else {
        return Err(0);
    };
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
        if !config.path_mask[FileEventNumber::MmapFile as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_MMAP_NAME_MAP,
                &FILEMON_FILTER_MMAP_PATH_MAP,
                &FILEMON_FILTER_MMAP_PREFIX_MAP,
            );
            let path =
                bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;
            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::MmapFile as usize],
                &event.path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    Ok(0)
}
#[map]
static FILEMON_FILTER_IOCTL_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_IOCTL_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_IOCTL_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_file_ioctl)
}

fn try_file_ioctl(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    filter_by_process(config, proc)?;

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::FileIoctl as u8;
    }
    let FileEventVariant::FileIoctl(ref mut event) = msg.event else {
        return Err(0);
    };
    unsafe {
        let fp: *const file = ctx.arg(0);
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.cmd = ctx.arg(1);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;
        // Filter event by path
        if !config.path_mask[FileEventNumber::FileIoctl as usize].is_empty() {
            let path_filter: PathFilter = PathFilter::new(
                &FILEMON_FILTER_IOCTL_NAME_MAP,
                &FILEMON_FILTER_IOCTL_PATH_MAP,
                &FILEMON_FILTER_IOCTL_PREFIX_MAP,
            );
            let path =
                bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

            let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
                .map_err(|_| 0i32)?;
            let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
                return Err(0);
            };
            let name = name_ptr.as_mut();
            let Some(name) = name else {
                return Err(0);
            };
            core::ptr::write_bytes(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
            bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
            if !path_filter.filter(
                config.path_mask[FileEventNumber::FileIoctl as usize],
                &event.path,
                name,
            ) {
                return Err(0);
            }
        }
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
