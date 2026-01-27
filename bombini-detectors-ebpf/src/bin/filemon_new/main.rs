#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{
        LpmTrie, LruHashMap, array::Array, hash_map::HashMap, lpm_trie::Key,
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};
use bombini_common::{
    config::{
        rule::Rules,
        rule::{FileNameMapKey, PathMapKey, PathPrefixMapKey},
    },
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
    vmlinux::{file, kgid_t, kuid_t, path, qstr},
};

use bombini_detectors_ebpf::filter::filemon::file_open::FileOpenFilter;

// Helpers
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
        core::ptr::write_bytes(&mut name.name as *mut u8, 0, MAX_FILENAME_SIZE);
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
        core::ptr::write_bytes(&mut path.path as *mut u8, 0, MAX_FILE_PATH);
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
        core::ptr::write_bytes(
            prefix.data.path_prefix.as_mut_ptr(),
            0,
            core::mem::size_of_val(&prefix.data.path_prefix),
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
pub fn file_open_modified(ctx: LsmContext) -> i32 {
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
        let file_path = fill_path_map!(FILEMON_PATH_MAP, path_ptr);

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
                let mut event_filter = interpreter::Interpreter::new(FileOpenFilter::new(
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
