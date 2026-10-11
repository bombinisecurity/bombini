#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_dynptr,
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf,
        bpf_probe_read_kernel_str_bytes,
        generated::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::{lsm, map},
    maps::{
        LpmTrie, LruHashMap, array::Array, hash_map::HashMap, lpm_trie::Key,
        per_cpu_array::PerCpuArray,
    },
    programs::LsmContext,
};
use bombini_common::{
    config::filemon::FileMonKernelConfig,
    config::rule::{
        AccessModeKey, CmdKey, CreationFlagsKey, FileNameMapKey, FlagsKey, ImodeKey, PathMapKey,
        PathPrefixMapKey, ProtModeKey, Rules, UIDKey,
    },
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::{
        Event, GenericEvent, MSG_FILE,
        file::{
            AccessMode, CreationFlags, FileEventNumber, FileEventVariant, FileMsg, Imode, ProtMode,
            SharingType,
        },
        process::ProcInfo,
    },
};
use bombini_detectors_ebpf::{
    co_re::{self, core_read_kernel},
    event_capture,
    filter::{
        filemon::{
            chmod::{ChmodFilter, ImodeValue},
            fileopen::{CreationFlagsValue, FileOpenFilter},
            mmap::{MmapFileFilter, MmapFlagsValue, ProtModeValue},
        },
        scope::ParentScopeFilter,
    },
    interpreter, util,
};

use bombini_detectors_ebpf::filter::filemon::{
    chown::ChownFilter, ioctl::FileIoctlFilter, path::PathFilter,
};

// Detector config
#[map]
static FILEMON_CONFIG: Array<FileMonKernelConfig> = Array::with_max_entries(1, 0);

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
            return Err(-1);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(-1);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
            return Err(-1);
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
        bpf_probe_read_kernel_str_bytes($src as *const u8, &mut name.name).map_err(|_| -1i32)?;
        name
    }};
}

/// Fill file path map
macro_rules! fill_path_map {
    ($map:ident, $src:expr) => {{
        let Some(path_ptr) = $map.get_ptr_mut(0) else {
            return Err(-1);
        };
        let path = path_ptr.as_mut();
        let Some(path) = path else {
            return Err(-1);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
            return Err(-1);
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
        bpf_probe_read_kernel_str_bytes($src as *const u8, &mut path.path).map_err(|_| -1i32)?;
        path
    }};
}

macro_rules! fill_prefix_map {
    ($map:ident, $src:expr) => {{
        let Some(prefix) = $map.get_ptr_mut(0) else {
            return Err(-1);
        };
        let prefix = prefix.as_mut();
        let Some(prefix) = prefix else {
            return Err(-1);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
            return Err(-1);
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

macro_rules! fill_parent_keys {
    ($proc:expr) => {{
        let ppid = $proc.ppid;
        let parent = PROCMON_PROC_MAP.get(&ppid);
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let (pname_src, ppath_src): (*const u8, *const u8) = match parent {
            Some(p) => (p.filename.as_ptr(), p.binary_path.as_ptr()),
            None => (zero_ptr as *const u8, zero_ptr as *const u8),
        };
        let parent_name = fill_name_map!(FILEMON_PARENT_FILE_NAME_MAP, pname_src);
        let parent_path = fill_path_map!(FILEMON_PARENT_PATH_MAP, ppath_src);
        let parent_prefix = fill_prefix_map!(FILEMON_PARENT_PATH_PREFIX_MAP, ppath_src);
        (parent_name, parent_path, parent_prefix)
    }};
}

macro_rules! get_key {
    ($map:ident) => {{
        let Some(key) = $map.get_ptr_mut(0) else {
            return Err(-1);
        };
        &mut *key
    }};
}

// Attribute helper maps
// Filter keys heap
#[repr(C)]
struct FilemonKeys {
    access_mode: AccessModeKey,
    creation_flags: CreationFlagsValue,
    imode: ImodeValue,
    owner_uid: UIDKey,
    owner_gid: UIDKey,
    prot_mode: ProtModeValue,
    mmap_flags: MmapFlagsValue,
}

#[map]
static FILEMON_KEYS_HEAP: PerCpuArray<FilemonKeys> = PerCpuArray::with_max_entries(1, 0);

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

#[map]
static FILEMON_PARENT_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_PARENT_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static FILEMON_PARENT_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
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
static FILEMON_FILE_OPEN_ACCESS_MODE_MAP: HashMap<AccessModeKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_CREATION_FLAGS_MAP: HashMap<CreationFlagsKey, CreationFlags> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_OPEN_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_open);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_open(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_FILE_OPEN_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::FileOpen as u8;
    }
    let FileEventVariant::FileOpen(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        // Get full path
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };

        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_flags = core_read_kernel!(fp, f_flags).unwrap_or(0);
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        event.access_mode = AccessMode::from_bits_truncate(1 << (f_flags & 3));
        event.creation_flags = CreationFlags::from_bits_truncate(f_flags);
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path)
            .map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            return enrich_file_open_event(msg, proc, fp, None);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::FileOpen as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(fp, f_path, dentry, d_name, name).ok_or(-1i32)?;
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);
        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // <VERIFIER_ISSUE>
        // Keep filter keys off the stack: the rule loop and predicate
        // bpf_loop callbacks add their frames to the combined 512 bytes limit.
        let Some(keys) = FILEMON_KEYS_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let keys = &mut *keys;
        keys.access_mode = AccessModeKey {
            access_mode: event.access_mode,
            rule_idx: 0,
        };

        keys.creation_flags = CreationFlagsValue {
            creation_flags: event.creation_flags,
            rule_idx: 0,
        };

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            let keys = get_key!(FILEMON_KEYS_HEAP);
            let access_mode = &mut keys.access_mode;
            let creation_flags = &mut keys.creation_flags;
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            access_mode.rule_idx = idx as u32;
            creation_flags.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_FILE_OPEN_BINNAME_MAP,
                    &FILEMON_FILE_OPEN_BINPATH_MAP,
                    &FILEMON_FILE_OPEN_BINPREFIX_MAP,
                    &FILEMON_FILE_OPEN_PBINNAME_MAP,
                    &FILEMON_FILE_OPEN_PBINPATH_MAP,
                    &FILEMON_FILE_OPEN_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(FileOpenFilter::new(
                    &FILEMON_FILE_OPEN_NAME_MAP,
                    &FILEMON_FILE_OPEN_PATH_MAP,
                    &FILEMON_FILE_OPEN_PREFIX_MAP,
                    &FILEMON_FILE_OPEN_ACCESS_MODE_MAP,
                    &FILEMON_FILE_OPEN_CREATION_FLAGS_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    access_mode,
                    creation_flags,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_file_open_event(msg, proc, fp, Some(idx as u8))?;
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_file_open_event(msg, proc, fp, Some(idx as u8))?;
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_file_open_event(msg, proc, fp, Some(idx as u8))?;
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
}

#[inline(always)]
fn enrich_file_open_event(
    msg: &mut FileMsg,
    proc: &ProcInfo,
    fp: co_re::file,
    rule_idx: Option<u8>,
) -> Result<i32, i32> {
    let FileEventVariant::FileOpen(ref mut event) = msg.event else {
        return Err(-1);
    };
    unsafe {
        let inode = core_read_kernel!(fp, f_inode).ok_or(-1i32)?;
        event.i_mode = Imode::from_bits_retain(inode.i_mode().ok_or(-1i32)?);
        event.uid = inode.i_uid();
        event.gid = inode.i_gid();
    }

    enrich_with_proc_info_and_rule_idx(msg, proc, rule_idx);

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

#[map]
static FILEMON_PATH_TRUNCATE_PBINPATH_MAP: HashMap<PathMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_TRUNCATE_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_truncate")]
pub fn path_truncate_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_truncate);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_truncate(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_PATH_TRUNCATE_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathTruncate as u8;
    }
    let FileEventVariant::PathTruncate(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        // Get full path
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };

        let p = co_re::path::from_ptr(ctx.arg(0));
        let _ = bpf_d_path(
            p.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, event).map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::PathTruncate as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(p, dentry, d_name, name).ok_or(-1i32)?;
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);
        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, event);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, event);

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_PATH_TRUNCATE_BINNAME_MAP,
                    &FILEMON_PATH_TRUNCATE_BINPATH_MAP,
                    &FILEMON_PATH_TRUNCATE_BINPREFIX_MAP,
                    &FILEMON_PATH_TRUNCATE_PBINNAME_MAP,
                    &FILEMON_PATH_TRUNCATE_PBINPATH_MAP,
                    &FILEMON_PATH_TRUNCATE_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_TRUNCATE_NAME_MAP,
                    &FILEMON_PATH_TRUNCATE_PATH_MAP,
                    &FILEMON_PATH_TRUNCATE_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
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

#[map]
static FILEMON_PATH_UNLINK_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_UNLINK_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_unlink")]
pub fn path_unlink_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_unlink);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_unlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_PATH_UNLINK_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathUnlink as u8;
    }
    let FileEventVariant::PathUnlink(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let p = co_re::path::from_ptr(ctx.arg(0));
        let len = bpf_d_path(
            p.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        if core::hint::black_box(len < 1) || len as usize > MAX_FILE_PATH - MAX_FILENAME_SIZE - 1 {
            return Err(-1);
        }
        let path_buf = path_ptr.as_mut();
        let Some(path_buf) = path_buf else {
            return Err(-1);
        };
        path_buf[len as usize - 1] = b'/';
        let entry = co_re::dentry::from_ptr(ctx.arg(1));
        let d_name = core_read_kernel!(entry, d_name, name).ok_or(-1i32)?;
        let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(-1);
        };
        bpf_probe_read_kernel_str_bytes(d_name, name).map_err(|_| -1i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, event).map_err(|_| -1i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event[len as usize..])
            .map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::PathUnlink as usize];

        // Get filtering attributes
        // Get file name
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, event);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, event);

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_PATH_UNLINK_BINNAME_MAP,
                    &FILEMON_PATH_UNLINK_BINPATH_MAP,
                    &FILEMON_PATH_UNLINK_BINPREFIX_MAP,
                    &FILEMON_PATH_UNLINK_PBINNAME_MAP,
                    &FILEMON_PATH_UNLINK_PBINPATH_MAP,
                    &FILEMON_PATH_UNLINK_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_UNLINK_NAME_MAP,
                    &FILEMON_PATH_UNLINK_PATH_MAP,
                    &FILEMON_PATH_UNLINK_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
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

#[map]
static FILEMON_PATH_SYMLINK_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_SYMLINK_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_symlink")]
pub fn path_symlink_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_symlink);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_symlink(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_PATH_SYMLINK_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathSymlink as u8;
    }
    let FileEventVariant::PathSymlink(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let p = co_re::path::from_ptr(ctx.arg(0));
        let len = bpf_d_path(
            p.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        if core::hint::black_box(len < 1) || len as usize > MAX_FILE_PATH - MAX_FILENAME_SIZE - 1 {
            return Err(-1);
        }
        let path_buf = path_ptr.as_mut();
        let Some(path_buf) = path_buf else {
            return Err(-1);
        };
        path_buf[len as usize - 1] = b'/';
        let entry = co_re::dentry::from_ptr(ctx.arg(1));
        let d_name = core_read_kernel!(entry, d_name, name).ok_or(-1i32)?;
        let Some(name_ptr) = FILENAME_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let name = name_ptr.as_mut();
        let Some(name) = name else {
            return Err(-1);
        };
        bpf_probe_read_kernel_str_bytes(d_name, name).map_err(|_| -1i32)?;
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.link_path)
            .map_err(|_| -1i32)?;
        bpf_probe_read_kernel_str_bytes(name.as_ptr(), &mut event.link_path[len as usize..])
            .map_err(|_| -1i32)?;
        // Get old path
        bpf_probe_read_kernel_str_bytes(ctx.arg(2), &mut event.old_path).map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::PathSymlink as usize];

        // Get filtering attributes
        // File name is not used in symlink, just copy old path for compatibility
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, &event.old_path as *const _);

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.old_path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.old_path);

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_PATH_SYMLINK_BINNAME_MAP,
                    &FILEMON_PATH_SYMLINK_BINPATH_MAP,
                    &FILEMON_PATH_SYMLINK_BINPREFIX_MAP,
                    &FILEMON_PATH_SYMLINK_PBINNAME_MAP,
                    &FILEMON_PATH_SYMLINK_PBINPATH_MAP,
                    &FILEMON_PATH_SYMLINK_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(PathFilter::new(
                    &FILEMON_PATH_SYMLINK_NAME_MAP,
                    &FILEMON_PATH_SYMLINK_PATH_MAP,
                    &FILEMON_PATH_SYMLINK_PREFIX_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
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
static FILEMON_PATH_CHMOD_IMODE_MAP: HashMap<ImodeKey, Imode> = HashMap::with_max_entries(1, 0);

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

#[map]
static FILEMON_PATH_CHMOD_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHMOD_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_chmod")]
pub fn path_chmod_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_chmod);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_chmod(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_PATH_CHMOD_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathChmod as u8;
    }
    let FileEventVariant::PathChmod(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let p = co_re::path::from_ptr(ctx.arg(0));
        event.i_mode = Imode::from_bits_retain(ctx.arg(1));
        let _ = bpf_d_path(
            p.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path)
            .map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::PathChmod as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(p, dentry, d_name, name).ok_or(-1i32)?;
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // <VERIFIER_ISSUE>
        // Keep filter keys off the stack: the rule loop and predicate
        // bpf_loop callbacks add their frames to the combined 512 bytes limit.
        let Some(keys) = FILEMON_KEYS_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let keys = &mut *keys;
        keys.imode = ImodeValue {
            imode: event.i_mode,
            rule_idx: 0,
        };

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            let keys = get_key!(FILEMON_KEYS_HEAP);
            let chomd_value = &mut keys.imode;
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            chomd_value.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_PATH_CHMOD_BINNAME_MAP,
                    &FILEMON_PATH_CHMOD_BINPATH_MAP,
                    &FILEMON_PATH_CHMOD_BINPREFIX_MAP,
                    &FILEMON_PATH_CHMOD_PBINNAME_MAP,
                    &FILEMON_PATH_CHMOD_PBINPATH_MAP,
                    &FILEMON_PATH_CHMOD_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(ChmodFilter::new(
                    &FILEMON_PATH_CHMOD_NAME_MAP,
                    &FILEMON_PATH_CHMOD_PATH_MAP,
                    &FILEMON_PATH_CHMOD_PREFIX_MAP,
                    &FILEMON_PATH_CHMOD_IMODE_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    chomd_value,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
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
static FILEMON_PATH_CHOWN_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_UID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_PATH_CHOWN_GID_MAP: HashMap<UIDKey, u8> = HashMap::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "path_chown")]
pub fn path_chown_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_chown);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_chown(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_PATH_CHOWN_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::PathChown as u8;
    }
    let FileEventVariant::PathChown(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let p = co_re::path::from_ptr(ctx.arg(0));
        event.uid = ctx.arg(1);
        event.gid = ctx.arg(2);
        let _ = bpf_d_path(
            p.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path)
            .map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::PathChown as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(p, dentry, d_name, name).ok_or(-1i32)?;
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);

        // Get UID
        // <VERIFIER_ISSUE>
        // Keep filter keys off the stack: the rule loop and predicate
        // bpf_loop callbacks add their frames to the combined 512 bytes limit.
        let Some(keys) = FILEMON_KEYS_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let keys = &mut *keys;
        keys.owner_uid = UIDKey {
            rule_idx: 0,
            value: event.uid,
        };

        // Get GID
        keys.owner_gid = UIDKey {
            rule_idx: 0,
            value: event.gid,
        };

        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            let keys = get_key!(FILEMON_KEYS_HEAP);
            let owner_uid = &mut keys.owner_uid;
            let owner_gid = &mut keys.owner_gid;
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            owner_uid.rule_idx = idx as u32;
            owner_gid.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_PATH_CHOWN_BINNAME_MAP,
                    &FILEMON_PATH_CHOWN_BINPATH_MAP,
                    &FILEMON_PATH_CHOWN_BINPREFIX_MAP,
                    &FILEMON_PATH_CHOWN_PBINNAME_MAP,
                    &FILEMON_PATH_CHOWN_PBINPATH_MAP,
                    &FILEMON_PATH_CHOWN_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(ChownFilter::new(
                    &FILEMON_PATH_CHOWN_NAME_MAP,
                    &FILEMON_PATH_CHOWN_PATH_MAP,
                    &FILEMON_PATH_CHOWN_PREFIX_MAP,
                    &FILEMON_PATH_CHOWN_UID_MAP,
                    &FILEMON_PATH_CHOWN_GID_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    owner_uid,
                    owner_gid,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
}

#[lsm(hook = "sb_mount")]
pub fn sb_mount_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_sb_mount);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_sb_mount(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::SbMount as u8;
    }
    let FileEventVariant::SbMount(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let dev: *const u8 = ctx.arg(0);
        let mnt = co_re::path::from_ptr(ctx.arg(1));
        bpf_probe_read_kernel_str_bytes(dev, &mut event.name).map_err(|_| -1i32)?;
        let _ = bpf_d_path(
            mnt.as_ptr() as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
        event.flags = ctx.arg(2);
    }

    enrich_with_proc_info_and_rule_idx(msg, proc, None);

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
static FILEMON_MMAP_FILE_PROT_MODE_MAP: HashMap<ProtModeKey, ProtMode> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_FLAGS_MAP: HashMap<FlagsKey, SharingType> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_MMAP_FILE_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[inline(always)]
fn is_null_pointer<T>(addr: *const T) -> bool {
    // <VERIFIER_ISSUE>
    // Check if the address is null. I don't know why, but checking
    // the null pointer with `is_null()` or explicitly comparing address to `0`
    // leads to a wrong behavior of ebpf program despite of correct ebpf bytecode.
    //
    // Since kernel 7.0 the file argument of mmap_file is trusted_ptr_or_null,
    // and the verifier prohibits pointer arithmetic on it until it is
    // null-checked. Comparing with `2` is not recognized as a null check, so
    // an explicit one is required too. black_box keeps LLVM from merging both
    // checks into a single `< 2` comparison.
    addr.is_null() || core::hint::black_box(addr).addr() < 2
}

#[lsm(hook = "mmap_file")]
pub fn mmap_file_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_mmap_file);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_mmap_file(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_MMAP_FILE_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::MmapFile as u8;
    }
    let FileEventVariant::MmapFile(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let fp = co_re::file::from_ptr(ctx.arg(0));
        event.prot = ProtMode::from_bits_truncate(ctx.arg(2));

        let mut flags_bits = ctx.arg::<u32>(3);
        let visibility = flags_bits & 0x3;
        if visibility == 0x3 {
            // if visibility is 0x3, it means that the mapping is MAP_SHARED_VALIDATE
            // so we set it to 0x4 to match the visibility enum
            flags_bits = flags_bits & !0x3 | 0x4;
        }
        event.flags = SharingType::from_bits_truncate(flags_bits);
        // <VERIFIER_ISSUE>
        // is_null_pointer instead of is_null().
        if !is_null_pointer(fp.as_ptr()) {
            let f_path = core_read_kernel!(fp, f_path).ok_or(0)?;
            let _ = bpf_d_path(
                f_path.as_ptr() as *mut aya_ebpf::bindings::path,
                path_ptr as *mut _,
                MAX_FILE_PATH as u32,
            );
            bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path)
                .map_err(|_| -1i32)?;
        }

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::MmapFile as usize];

        // Get filtering attributes
        // Get file name
        // <VERIFIER_ISSUE>
        // is_null_pointer instead of is_null().
        let _ = if !is_null_pointer(fp.as_ptr()) {
            let d_name = core_read_kernel!(fp, f_path, dentry, d_name, name).ok_or(-1i32)?;
            fill_name_map!(FILEMON_FILE_NAME_MAP, d_name)
        } else {
            fill_name_map!(FILEMON_FILE_NAME_MAP, &event.path)
        };

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // <VERIFIER_ISSUE>
        // Keep filter keys off the stack: the rule loop and predicate
        // bpf_loop callbacks add their frames to the combined 512 bytes limit.
        let Some(keys) = FILEMON_KEYS_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        let keys = &mut *keys;
        keys.prot_mode = ProtModeValue {
            prot_mode: event.prot,
            rule_idx: 0,
        };

        keys.mmap_flags = MmapFlagsValue {
            flags: event.flags,
            rule_idx: 0,
        };

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        let _ = fill_parent_keys!(proc);
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            let keys = get_key!(FILEMON_KEYS_HEAP);
            let prot_mode = &mut keys.prot_mode;
            let flags = &mut keys.mmap_flags;
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            prot_mode.rule_idx = idx as u8;
            flags.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_MMAP_FILE_BINNAME_MAP,
                    &FILEMON_MMAP_FILE_BINPATH_MAP,
                    &FILEMON_MMAP_FILE_BINPREFIX_MAP,
                    &FILEMON_MMAP_FILE_PBINNAME_MAP,
                    &FILEMON_MMAP_FILE_PBINPATH_MAP,
                    &FILEMON_MMAP_FILE_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
                let mut event_filter = interpreter::Interpreter::new(MmapFileFilter::new(
                    &FILEMON_MMAP_FILE_NAME_MAP,
                    &FILEMON_MMAP_FILE_PATH_MAP,
                    &FILEMON_MMAP_FILE_PREFIX_MAP,
                    &FILEMON_MMAP_FILE_PROT_MODE_MAP,
                    &FILEMON_MMAP_FILE_FLAGS_MAP,
                    file_name,
                    file_path,
                    file_prefix,
                    prot_mode,
                    flags,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
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

#[map]
static FILEMON_FILE_IOCTL_PBINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_PBINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILE_IOCTL_PBINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_FILE, true, try_file_ioctl);
    // <VERIFIER_ISSUE>
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_file_ioctl(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::File(ref mut msg) = generic_event.event else {
        return Err(-1);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(pid) };
    let Some(proc) = proc else {
        return Err(-1);
    };

    let Some(rules) = FILEMON_FILE_IOCTL_RULE_MAP.get(0) else {
        return Err(-1);
    };

    unsafe {
        let p = &mut msg.event as *mut FileEventVariant as *mut u8;
        *p = FileEventNumber::FileIoctl as u8;
    }
    let FileEventVariant::FileIoctl(ref mut event) = msg.event else {
        return Err(-1);
    };

    unsafe {
        let fp = co_re::file::from_ptr(ctx.arg(0));
        let f_path = core_read_kernel!(fp, f_path).ok_or(-1i32)?;
        let inode = core_read_kernel!(fp, f_inode).ok_or(-1i32)?;
        let Some(path_ptr) = PATH_HEAP.get_ptr_mut(0) else {
            return Err(-1);
        };
        event.i_mode = Imode::from_bits_retain(inode.i_mode().ok_or(-1i32)?);
        event.cmd = ctx.arg(1);
        let _ = bpf_d_path(
            f_path.as_ptr() as *mut aya_ebpf::bindings::path,
            path_ptr as *mut _,
            MAX_FILE_PATH as u32,
        );
        bpf_probe_read_kernel_str_bytes(path_ptr as *const _, &mut event.path)
            .map_err(|_| -1i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
            return Err(-1);
        };
        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(-1);
        };

        let sandbox: Option<bool> = config.sandbox_mode[FileEventNumber::FileIoctl as usize];

        // Get filtering attributes
        // Get file name
        let d_name = core_read_kernel!(fp, f_path, dentry, d_name, name).ok_or(-1i32)?;
        let _ = fill_name_map!(FILEMON_FILE_NAME_MAP, d_name);

        // Get file path
        let _ = fill_path_map!(FILEMON_PATH_MAP, &event.path);

        // Get file prefix
        let _ = fill_prefix_map!(FILEMON_PATH_PREFIX_MAP, &event.path);

        // Get binary name
        let _ = fill_name_map!(FILEMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let _ = fill_path_map!(FILEMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let _ = fill_prefix_map!(FILEMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        let _ = fill_parent_keys!(proc);
        // Get Cmd
        let mut cmd = CmdKey {
            rule_idx: 0,
            value: event.cmd,
        };
        let mut result: Result<i32, i32> = Err(0);
        interpreter::for_each_rule(rule_array, |idx, rule| {
            // <VERIFIER_ISSUE>
            // Get filter keys inside the rule callback instead of capturing
            // them: captured pointers bloat the closure context and the main
            // frame, which exceeds the combined 512 bytes stack limit.
            let file_name = get_key!(FILEMON_FILE_NAME_MAP);
            let file_path = get_key!(FILEMON_PATH_MAP);
            let file_prefix = get_key!(FILEMON_PATH_PREFIX_MAP);
            let binary_name = get_key!(FILEMON_BINARY_FILE_NAME_MAP);
            let binary_path = get_key!(FILEMON_BINARY_PATH_MAP);
            let binary_prefix = get_key!(FILEMON_BINARY_PATH_PREFIX_MAP);
            let parent_name = get_key!(FILEMON_PARENT_FILE_NAME_MAP);
            let parent_path = get_key!(FILEMON_PARENT_PATH_MAP);
            let parent_prefix = get_key!(FILEMON_PARENT_PATH_PREFIX_MAP);
            file_name.rule_idx = idx as u8;
            file_path.rule_idx = idx as u8;
            file_prefix.data.rule_idx = idx as u8;
            cmd.rule_idx = idx as u32;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            parent_name.rule_idx = idx as u8;
            parent_path.rule_idx = idx as u8;
            parent_prefix.data.rule_idx = idx as u8;
            // <VERIFIER_ISSUE>
            // Limit the scope filter lifetime, so its stack slots are reused by
            // the event filter. Otherwise the rule callback frame exceeds the
            // combined 512 bytes stack limit.
            let scope_passed = {
                let mut scope_filter = interpreter::Interpreter::new(ParentScopeFilter::new(
                    &FILEMON_FILE_IOCTL_BINNAME_MAP,
                    &FILEMON_FILE_IOCTL_BINPATH_MAP,
                    &FILEMON_FILE_IOCTL_BINPREFIX_MAP,
                    &FILEMON_FILE_IOCTL_PBINNAME_MAP,
                    &FILEMON_FILE_IOCTL_PBINPATH_MAP,
                    &FILEMON_FILE_IOCTL_PBINPREFIX_MAP,
                    binary_name,
                    binary_path,
                    binary_prefix,
                    parent_name,
                    parent_path,
                    parent_prefix,
                ))?;
                scope_filter.check_predicate(&rule.scope)?
            };
            if scope_passed {
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
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        result = Ok(0);
                        return Ok(true);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        result = Ok(-1);
                        return Ok(true);
                    }
                    // allow list is satisfied: do not send event
                    result = Err(0);
                    return Ok(true);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    result = Ok(-1);
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        result
    }
}

#[inline(always)]
fn enrich_with_proc_info_and_rule_idx(msg: &mut FileMsg, proc: &ProcInfo, rule_idx: Option<u8>) {
    msg.rule_idx = rule_idx;

    if let Some(parent) = unsafe { PROCMON_PROC_MAP.get(proc.ppid) } {
        msg.parent.pid = parent.pid;
        msg.parent.start = parent.start;
    }

    util::process_key_init(&mut msg.process, proc);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
