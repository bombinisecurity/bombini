#![no_std]
#![no_main]

mod file_open;

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{LpmTrie, LruHashMap, array::Array, hash_map::HashMap, per_cpu_array::PerCpuArray},
    programs::LsmContext,
};
use bombini_common::{
    config::rule::Rule,
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::{
        Event, GenericEvent, MSG_FILE,
        file::{FileEventNumber, FileEventVariant},
        process::ProcInfo,
    },
};
use bombini_detectors_ebpf::{
    event_capture,
    event_map::rb_event_init,
    interpreter::{self},
    util,
    vmlinux::{file, kgid_t, kuid_t, path, qstr},
};

use crate::file_open::FileOpenFilter;

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_RULE_MAP: Array<Rule> = Array::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PATH_MAP: HashMap<[u8; MAX_FILE_PATH], u64> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_NAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u64> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u64> =
    LpmTrie::with_max_entries(1, 0);

#[lsm(hook = "file_open")]
pub fn file_open_modified(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_open)
}

fn try_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Some(rule) = FILEMON_FILE_OPEN_RULE_MAP.get(0) else {
        return Err(0);
    };
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // TODO: Filter by process here

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::FileOpen as u8;
    }
    let FileEventVariant::FileOpen(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        // Get full path
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let name = path_ptr.as_mut();
        let Some(name) = name else {
            return Err(0);
        };
        aya_ebpf::memset(name.as_mut_ptr(), 0, MAX_FILE_PATH);

        let fp: *const file = ctx.arg(0);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;

        // Get file name
        let path = bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(0);
        };
        aya_ebpf::memset(name.as_mut_ptr(), 0, MAX_FILENAME_SIZE);
        bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;

        // Filter events
        let mut interpreter = interpreter::Interpreter::new(FileOpenFilter {
            name_map: &FILEMON_FILE_OPEN_NAME_MAP,
            path_map: &FILEMON_FILE_OPEN_PATH_MAP,
            prefix_map: &FILEMON_FILE_OPEN_PREFIX_MAP,

            name,
            path: &event.path,
        });

        let verdict = interpreter.check_predicate(&rule.event);
        if verdict.is_err() || !verdict.unwrap() {
            return Err(0);
        }

        // Fill event
        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read_kernel::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read_kernel::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
    }

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(&proc.ppid) } {
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
