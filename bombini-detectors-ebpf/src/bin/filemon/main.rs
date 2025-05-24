#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{array::Array, hash_map::HashMap},
    programs::LsmContext,
};

use bombini_common::config::filemon::Config;

use bombini_common::event::file::{HOOK_FILE_OPEN, HOOK_PATH_TRUNCATE, HOOK_PATH_UNLINK};
use bombini_common::event::process::{ProcInfo, MAX_FILENAME_SIZE};
use bombini_common::event::{Event, MSG_FILE};
use bombini_detectors_ebpf::vmlinux::{dentry, file, fmode_t, kgid_t, kuid_t, path, qstr};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1024, 0);

#[map]
static FILEMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

const FMODE_EXEC: u32 = 1 << 5;

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return 0;
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return 0;
    };
    event_capture!(
        ctx,
        MSG_FILE,
        false,
        try_open,
        config.file_open_config.expose_events
    )
}

fn try_open(ctx: LsmContext, event: &mut Event, expose: bool) -> Result<i32, i32> {
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
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
            event.path.as_mut_ptr() as *mut i8,
            event.path.len() as u32,
        );
        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
    }

    if expose {
        util::copy_proc(proc, &mut event.process);
        return Ok(0);
    }

    Err(0)
}

#[lsm(hook = "path_truncate")]
pub fn path_truncate_capture(ctx: LsmContext) -> i32 {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return 0;
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return 0;
    };
    event_capture!(
        ctx,
        MSG_FILE,
        true,
        try_truncate,
        config.path_truncate_config.expose_events
    )
}

fn try_truncate(ctx: LsmContext, event: &mut Event, expose: bool) -> Result<i32, i32> {
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
    event.hook = HOOK_PATH_TRUNCATE;
    unsafe {
        let p: *const path = ctx.arg(0);
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut i8,
            event.path.len() as u32,
        );
    }

    if expose {
        util::copy_proc(proc, &mut event.process);
        return Ok(0);
    }

    Err(0)
}

#[lsm(hook = "path_unlink")]
pub fn path_unlink_capture(ctx: LsmContext) -> i32 {
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return 0;
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return 0;
    };
    event_capture!(
        ctx,
        MSG_FILE,
        false,
        try_unlink,
        config.path_unlink_config.expose_events
    )
}

fn try_unlink(ctx: LsmContext, event: &mut Event, expose: bool) -> Result<i32, i32> {
    let Event::File(event) = event else {
        return Err(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };
    event.hook = HOOK_PATH_UNLINK;
    unsafe {
        let p: *const path = ctx.arg(0);
        let entry: *const dentry = ctx.arg(1);
        let d_name = bpf_probe_read::<qstr>(&(*entry).d_name as *const _).map_err(|_| 0i32)?;
        aya_ebpf::memset(event.name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, &mut event.name).map_err(|_| 0i32)?;
        let _ = bpf_d_path(
            p as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut i8,
            event.path.len() as u32,
        );
    }

    if expose {
        util::copy_proc(proc, &mut event.process);
        return Ok(0);
    }

    Err(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
