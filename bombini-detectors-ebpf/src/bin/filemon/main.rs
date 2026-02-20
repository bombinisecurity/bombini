#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_dynptr,
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
        r#gen::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::{lsm, map},
    maps::{
        LpmTrie, LruHashMap, array::Array, hash_map::HashMap, lpm_trie::Key,
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};
use bombini_common::{
    config::rule::{CmdKey, FileNameMapKey, PathMapKey, PathPrefixMapKey, Rules, UIDKey},
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::{
        Event, GenericEvent, MSG_FILE,
        file::{FileEventNumber, FileEventVariant, FileMsg},
        process::ProcInfo,
    },
};
use bombini_detectors_ebpf::{
    event_capture,
    event_map::rb_event_init,
    filter::scope::ScopeFilter,
    interpreter::{self, rule::IsEmpty},
    util,
    vmlinux::{dentry, file, kgid_t, kuid_t, path, qstr},
};

use bombini_detectors_ebpf::filter::filemon::{
    chown::ChownFilter, ioctl::FileIoctlFilter, path::PathFilter,
};

// Helpers
#[map]
static ZERO_PATH_MAP: Array<[u8; MAX_FILE_PATH]> = Array::with_max_entries(1, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

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
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
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
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
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
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
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

// Attribute helper maps
#[map]
static FILEMON_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_BINARY_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_BINARY_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_BINARY_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

// Rules maps
#[map]
static FILEMON_FILE_OPEN_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter file open maps begin
#[map]
static FILEMON_FILE_OPEN_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_open)
}

fn try_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_FILE_OPEN_RULE_MAP.get(0) else {
        return Err(0);
    };

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

        let fp: *const file = ctx.arg(0);
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path).map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            return enrich_file_open_event(msg, proc, fp);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_FILE_OPEN_BINNAME_MAP,
                &FILEMON_FILE_OPEN_BINPATH_MAP,
                &FILEMON_FILE_OPEN_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_FILE_OPEN_NAME_MAP,
                    &FILEMON_FILE_OPEN_PATH_MAP,
                    &FILEMON_FILE_OPEN_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    return enrich_file_open_event(msg, proc, fp);
                }
            }
        }
    }

    Err(0)
}

#[inline(always)]
fn enrich_file_open_event(msg: &mut FileMsg, proc: &ProcInfo, fp: *const file) -> Result<i32, i32> {
    let FileEventVariant::FileOpen(ref mut event) = msg.event else {
        return Err(0);
    };
    unsafe {
        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read_kernel::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read_kernel::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
    }

    enrich_with_proc_info(msg, proc);

    Ok(0)
}

// Path truncate rules maps
#[map]
static FILEMON_PATH_TRUNCATE_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter path truncate maps begin
#[map]
static FILEMON_PATH_TRUNCATE_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_NAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_truncate")]
pub fn path_truncate_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_truncate)
}

fn try_truncate(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_PATH_TRUNCATE_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathTruncate as u8;
    }
    let FileEventVariant::PathTruncate(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        // Get full path
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

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, event);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, event);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_PATH_TRUNCATE_BINNAME_MAP,
                &FILEMON_PATH_TRUNCATE_BINPATH_MAP,
                &FILEMON_PATH_TRUNCATE_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_TRUNCATE_NAME_MAP,
                    &FILEMON_PATH_TRUNCATE_PATH_MAP,
                    &FILEMON_PATH_TRUNCATE_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
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

// Path unlink rules maps
#[map]
static FILEMON_PATH_UNLINK_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter path unlink maps begin
#[map]
static FILEMON_PATH_UNLINK_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_unlink")]
pub fn path_unlink_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_unlink)
}

fn try_unlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_PATH_UNLINK_RULE_MAP.get(0) else {
        return Err(0);
    };

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
        bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, event).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event[len as usize..])
            .map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, event);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, event);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_PATH_UNLINK_BINNAME_MAP,
                &FILEMON_PATH_UNLINK_BINPATH_MAP,
                &FILEMON_PATH_UNLINK_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_UNLINK_NAME_MAP,
                    &FILEMON_PATH_UNLINK_PATH_MAP,
                    &FILEMON_PATH_UNLINK_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
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

// Path symlink rules maps
#[map]
static FILEMON_PATH_SYMLINK_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter path symlink maps begin
#[map]
static FILEMON_PATH_SYMLINK_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_symlink")]
pub fn path_symlink_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_symlink)
}

fn try_symlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_PATH_SYMLINK_RULE_MAP.get(0) else {
        return Err(0);
    };

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
        bpf_probe_read_kernel_str_bytes(d_name.name, name).map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.link_path)
            .map_err(|_| 0i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event.link_path[len as usize..])
            .map_err(|_| 0i32)?;
        // Get old path
        bpf_probe_read_kernel_str_bytes(ctx.arg(2), &mut event.old_path).map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // File name is not used in symlink, just copy old path for compatibility
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, &event.old_path as *const _);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.old_path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.old_path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_PATH_SYMLINK_BINNAME_MAP,
                &FILEMON_PATH_SYMLINK_BINPATH_MAP,
                &FILEMON_PATH_SYMLINK_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_SYMLINK_NAME_MAP,
                    &FILEMON_PATH_SYMLINK_PATH_MAP,
                    &FILEMON_PATH_SYMLINK_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
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

// Path chmod rules maps
#[map]
static FILEMON_PATH_CHMOD_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter path chmod maps begin
#[map]
static FILEMON_PATH_CHMOD_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_chmod")]
pub fn path_chmod_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_chmod)
}

fn try_chmod(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_PATH_CHMOD_RULE_MAP.get(0) else {
        return Err(0);
    };

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

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_PATH_CHMOD_BINNAME_MAP,
                &FILEMON_PATH_CHMOD_BINPATH_MAP,
                &FILEMON_PATH_CHMOD_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_CHMOD_NAME_MAP,
                    &FILEMON_PATH_CHMOD_PATH_MAP,
                    &FILEMON_PATH_CHMOD_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
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

// Path chown rules maps
#[map]
static FILEMON_PATH_CHOWN_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter path chown maps begin
#[map]
static FILEMON_PATH_CHOWN_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_UID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_GID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_chown")]
pub fn path_chown_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_chown)
}

fn try_chown(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_PATH_CHOWN_RULE_MAP.get(0) else {
        return Err(0);
    };

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

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(p).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        // Get UID
        let mut owner_uid = UIDKey {
            rule_idx: 0,
            uid: event.uid,
        };

        // Get GID
        let mut owner_gid = UIDKey {
            rule_idx: 0,
            uid: event.gid,
        };

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            owner_uid.rule_idx = idx as u32;
            owner_gid.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_PATH_CHOWN_BINNAME_MAP,
                &FILEMON_PATH_CHOWN_BINPATH_MAP,
                &FILEMON_PATH_CHOWN_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(ChownFilter::new(
                    &FILEMON_PATH_CHOWN_NAME_MAP,
                    &FILEMON_PATH_CHOWN_PATH_MAP,
                    &FILEMON_PATH_CHOWN_PREFIX_MAP,
                    &FILEMON_PATH_CHOWN_UID_MAP,
                    &FILEMON_PATH_CHOWN_GID_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    &owner_uid,
                    &owner_gid,
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

#[lsm(hook = "sb_mount")]
pub fn sb_mount_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_sb_mount)
}

fn try_sb_mount(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

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

    enrich_with_proc_info(msg, proc);

    Ok(0)
}

// Mmap file rules maps
#[map]
static FILEMON_MMAP_FILE_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter mmap file maps begin
#[map]
static FILEMON_MMAP_FILE_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "mmap_file")]
pub fn mmap_file_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_mmap_file)
}

fn try_mmap_file(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_MMAP_FILE_RULE_MAP.get(0) else {
        return Err(0);
    };

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

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_MMAP_FILE_BINNAME_MAP,
                &FILEMON_MMAP_FILE_BINPATH_MAP,
                &FILEMON_MMAP_FILE_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_MMAP_FILE_NAME_MAP,
                    &FILEMON_MMAP_FILE_PATH_MAP,
                    &FILEMON_MMAP_FILE_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
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

// File ioctl rules maps
#[map]
static FILEMON_FILE_IOCTL_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Filter file ioctl maps begin
#[map]
static FILEMON_FILE_IOCTL_PATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_NAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_CMD_MAP: HashMap<CmdKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_PREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, true, try_file_ioctl)
}

fn try_file_ioctl(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = FILEMON_FILE_IOCTL_RULE_MAP.get(0) else {
        return Err(0);
    };

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

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info(msg, proc);
            return Ok(0);
        };

        // Get filtering attributes
        // Get file name
        let path = bpf_probe_read_kernel::<path>(&(*fp).f_path as *const _).map_err(|_| 0i32)?;

        let d_name = bpf_probe_read_kernel::<qstr>(&(*(path.dentry)).d_name as *const _)
            .map_err(|_| 0i32)?;
        let file_name = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name.name);

        // Get file path
        let file_path = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let file_prefix = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let binary_name = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        // Get Cmd
        let mut cmd = CmdKey {
            rule_idx: 0,
            uid: event.cmd,
        };
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            cmd.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &FILEMON_FILE_IOCTL_BINNAME_MAP,
                &FILEMON_FILE_IOCTL_BINPATH_MAP,
                &FILEMON_FILE_IOCTL_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(FileIoctlFilter::new(
                    &FILEMON_FILE_IOCTL_NAME_MAP,
                    &FILEMON_FILE_IOCTL_PATH_MAP,
                    &FILEMON_FILE_IOCTL_PREFIX_MAP,
                    &FILEMON_FILE_IOCTL_CMD_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    &cmd,
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

#[inline(always)]
fn enrich_with_proc_info(msg: &mut FileMsg, proc: &ProcInfo) {
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
