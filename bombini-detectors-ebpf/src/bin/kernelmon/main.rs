#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_cmd::BPF_PROG_LOAD, bpf_dynptr},
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
        r#gen::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, lpm_trie::Key},
    programs::LsmContext,
};
use bombini_common::{
    config::{
        kernelmon::KernelMonKernelConfig,
        rule::{
            BpfIdKey, BpfMapTypeKey, BpfNameKey, BpfPrefixKey, BpfProgTypeKey, FileNameMapKey,
            PathMapKey, PathPrefixMapKey, Rules,
        },
    },
    constants::{MAX_BPFNAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::{
        Event, GenericEvent, MSG_KERNEL,
        file::AccessMode,
        kernel::{BpfMapType, BpfProgType, KernelEventNumber, KernelEventVariant, KernelMsg},
        process::ProcInfo,
    },
};
use bombini_detectors_ebpf::{
    co_re::{self, core_read_kernel},
    filter::{
        kernelmon::{bpfmap::BpfMapFilter, bpfprog::BpfProgFilter},
        scope::ScopeFilter,
    },
    interpreter::{self, rule::IsEmpty},
    util,
    vmlinux::{bpf_map, bpf_prog},
};
use bombini_detectors_ebpf::{event_capture, vmlinux::bpf_attr__bindgen_ty_4};

// Detector config
#[map]
static KERNELMON_CONFIG: Array<KernelMonKernelConfig> = Array::with_max_entries(1, 0);

// Helpers
#[map]
static ZERO_PATH_MAP: Array<[u8; MAX_FILE_PATH]> = Array::with_max_entries(1, 0);

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static FILENAME_HEAP: PerCpuArray<[u8; MAX_FILENAME_SIZE]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PATH_HEAP: PerCpuArray<[u8; MAX_FILE_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn is_null_pointer<T>(addr: *const T) -> bool {
    // Check if the address is null. I don't know why, but checking
    // the null pointer with `is_null()` or explicitly comparing address to `0`
    // leads to a wrong behavior of ebpf program despite of correct ebpf bytecode.
    addr.addr() < 2
}

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
        {
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
        }
        let clear_stack = 0u64;
        core::hint::black_box(&clear_stack);

        bpf_probe_read_kernel_buf($src as *const u8, &mut prefix.data.path_prefix)
            .map_err(|_| 0i32)?;

        prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
        prefix
    }};
}

// Attribute helpers maps
#[map]
static KERNELMON_BINARY_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static KERNELMON_BINARY_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static KERNELMON_BINARY_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

// Bpf map rules maps
#[map]
static KERNELMON_BPF_MAP_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Bpf map maps begin
#[map]
static KERNELMON_BPF_MAP_ID_MAP: HashMap<BpfIdKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_TYPE_MAP: HashMap<BpfMapTypeKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_NAME_MAP: HashMap<BpfNameKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_PREFIX_MAP: LpmTrie<BpfPrefixKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "bpf_map")]
pub fn bpf_map_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_KERNEL, true, try_bpf_map)
}

fn try_bpf_map(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Kernel(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = KERNELMON_BPF_MAP_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut KernelEventVariant as *mut u8;
        *p = KernelEventNumber::BpfMapAccess as u8;
    }
    let KernelEventVariant::BpfMapAccess(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let bpf_map = co_re::bpf_map::from_ptr(ctx.arg(0));
        let flags: u32 = ctx.arg(1);
        if is_null_pointer(bpf_map.as_ptr()) {
            return Err(0);
        }
        event.id = core_read_kernel!(bpf_map, id).ok_or(0i32)?;
        event.map_type = core::mem::transmute::<u32, BpfMapType>((*(bpf_map.as_ptr())).map_type);
        // Flags is either 1, 2 or 3.
        event.access_mode = AccessMode::from_bits_truncate(1 << ((flags & 3).max(1) - 1));
        bpf_probe_read_kernel_str_bytes(
            (*(bpf_map.as_ptr())).name.as_slice() as *const [i8] as *const _,
            &mut event.name,
        )
        .map_err(|_| 0i32)?;
        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = KERNELMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };

        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[KernelEventNumber::BpfMapAccess as usize];

        // Get filtering attributes
        // Get bpf map id
        let mut bpf_id = BpfIdKey {
            rule_idx: 0,
            value: event.id,
        };

        // Get bpf map type
        let mut bpf_map_type = BpfMapTypeKey {
            rule_idx: 0,
            map_type: event.map_type,
        };

        // Get bpf map name
        let mut bpf_name = BpfNameKey {
            rule_idx: 0,
            name: event.name,
        };

        let mut bpf_prefix = Key {
            prefix_len: (MAX_BPFNAME_SIZE * 8) as u32,
            data: BpfPrefixKey {
                name: event.name,
                rule_idx: 0,
            },
        };

        // Get binary name
        let binary_name = fill_name_map!(KERNELMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(KERNELMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(KERNELMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            bpf_id.rule_idx = idx as u32;
            bpf_map_type.rule_idx = idx as u32;
            bpf_name.rule_idx = idx as u8;
            bpf_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &KERNELMON_BPF_MAP_BINNAME_MAP,
                &KERNELMON_BPF_MAP_BINPATH_MAP,
                &KERNELMON_BPF_MAP_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(BpfMapFilter::new(
                    &KERNELMON_BPF_MAP_ID_MAP,
                    &KERNELMON_BPF_MAP_TYPE_MAP,
                    &KERNELMON_BPF_MAP_NAME_MAP,
                    &KERNELMON_BPF_MAP_PREFIX_MAP,
                    &bpf_id,
                    &bpf_map_type,
                    &bpf_name,
                    &bpf_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            } else if let Some(deny_list) = sandbox
                && !deny_list
            {
                // allow list is not satisfied: send event
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                msg.blocked = true;
                return Ok(-1);
            }
        }
    }
    Err(0)
}

// Bpf map rules maps
#[map]
static KERNELMON_BPF_MAP_CREATE_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Bpf map maps begin
#[map]
// ID is not assigned to bpf map at creation time, so we cannot filter by it
static KERNELMON_BPF_MAP_CREATE_ID_STUB_MAP: HashMap<BpfIdKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_TYPE_MAP: HashMap<BpfMapTypeKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_NAME_MAP: HashMap<BpfNameKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_PREFIX_MAP: LpmTrie<BpfPrefixKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_BINPATH_MAP: HashMap<PathMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_MAP_CREATE_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

// Before 6.9 kernel
#[lsm(hook = "bpf_map_alloc_security")]
pub fn bpf_map_alloc_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_KERNEL, true, try_bpf_map_create);
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

// After 6.9 kernel
#[lsm(hook = "bpf_map_create")]
pub fn bpf_map_create_capture(ctx: LsmContext) -> i32 {
    let exit_code = event_capture!(ctx, MSG_KERNEL, true, try_bpf_map_create);
    // Verifier cannot determine that return value is in [-4096, 0]
    if exit_code != 0 { -1 } else { 0 }
}

fn try_bpf_map_create(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Kernel(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = KERNELMON_BPF_MAP_CREATE_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut KernelEventVariant as *mut u8;
        *p = KernelEventNumber::BpfMapCreate as u8;
    }
    let KernelEventVariant::BpfMapCreate(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let bpf_map: *const bpf_map = ctx.arg(0);
        if is_null_pointer(bpf_map) {
            return Err(0);
        }
        event.map_type = core::mem::transmute::<u32, BpfMapType>((*bpf_map).map_type);
        bpf_probe_read_kernel_str_bytes((*bpf_map).name.as_ptr() as *const u8, &mut event.name)
            .map_err(|_| 0i32)?;
        event.key_size = (*bpf_map).key_size;
        event.value_size = (*bpf_map).value_size;
        event.max_entries = (*bpf_map).max_entries;
        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = KERNELMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };

        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[KernelEventNumber::BpfMapCreate as usize];

        // Get filtering attributes
        // Just stubbing the id, since it is not assigned at creation time
        let mut bpf_id = BpfIdKey {
            rule_idx: 0,
            value: 0,
        };

        // Get bpf map type
        let mut bpf_map_type = BpfMapTypeKey {
            rule_idx: 0,
            map_type: event.map_type,
        };

        // Get bpf map name
        let mut bpf_name = BpfNameKey {
            rule_idx: 0,
            name: event.name,
        };

        let mut bpf_prefix = Key {
            prefix_len: (MAX_BPFNAME_SIZE * 8) as u32,
            data: BpfPrefixKey {
                name: event.name,
                rule_idx: 0,
            },
        };

        // Get binary name
        let binary_name = fill_name_map!(KERNELMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(KERNELMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(KERNELMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            bpf_id.rule_idx = idx as u32;
            bpf_map_type.rule_idx = idx as u32;
            bpf_name.rule_idx = idx as u8;
            bpf_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &KERNELMON_BPF_MAP_CREATE_BINNAME_MAP,
                &KERNELMON_BPF_MAP_CREATE_BINPATH_MAP,
                &KERNELMON_BPF_MAP_CREATE_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(BpfMapFilter::new(
                    &KERNELMON_BPF_MAP_CREATE_ID_STUB_MAP,
                    &KERNELMON_BPF_MAP_CREATE_TYPE_MAP,
                    &KERNELMON_BPF_MAP_CREATE_NAME_MAP,
                    &KERNELMON_BPF_MAP_CREATE_PREFIX_MAP,
                    &bpf_id,
                    &bpf_map_type,
                    &bpf_name,
                    &bpf_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            } else if let Some(deny_list) = sandbox
                && !deny_list
            {
                // allow list is not satisfied: send event
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                msg.blocked = true;
                return Ok(-1);
            }
        }
    }
    Err(0)
}

// Bpf prog rules maps
#[map]
static KERNELMON_BPF_PROG_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Bpf prog maps begin
#[map]
static KERNELMON_BPF_PROG_ID_MAP: HashMap<BpfIdKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_TYPE_MAP: HashMap<BpfProgTypeKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_NAME_MAP: HashMap<BpfNameKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_PREFIX_MAP: LpmTrie<BpfPrefixKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

#[lsm(hook = "bpf_prog")]
pub fn bpf_prog_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_KERNEL, true, try_bpf_prog)
}

fn try_bpf_prog(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Kernel(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = KERNELMON_BPF_PROG_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut KernelEventVariant as *mut u8;
        *p = KernelEventNumber::BpfProgAccess as u8;
    }
    let KernelEventVariant::BpfProgAccess(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let bpf_prog: *const bpf_prog = ctx.arg(0);
        if is_null_pointer(bpf_prog) {
            return Err(0);
        }
        if is_null_pointer((*bpf_prog).aux) {
            return Err(0);
        }
        event.id = (*(*bpf_prog).aux).id;
        event.prog_type = core::mem::transmute::<u32, BpfProgType>((*bpf_prog).type_);
        bpf_probe_read_kernel_str_bytes(
            (*(*bpf_prog).aux).name.as_ptr() as *const u8,
            &mut event.name,
        )
        .map_err(|_| 0i32)?;
        // Hook is only available for LSM & Tracepoint, for other types, attach_func_name is NULL
        let _ = bpf_probe_read_kernel_str_bytes(
            (*(*bpf_prog).aux).attach_func_name as *const _,
            &mut event.hook,
        );

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = KERNELMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };

        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[KernelEventNumber::BpfMapAccess as usize];

        // Get filtering attributes
        // Get bpf map id
        let mut bpf_id = BpfIdKey {
            rule_idx: 0,
            value: event.id,
        };

        // Get bpf map type
        let mut bpf_prog_type = BpfProgTypeKey {
            rule_idx: 0,
            prog_type: event.prog_type,
        };

        // Get bpf map name
        let mut bpf_name = BpfNameKey {
            rule_idx: 0,
            name: event.name,
        };

        let mut bpf_prefix = Key {
            prefix_len: (MAX_BPFNAME_SIZE * 8) as u32,
            data: BpfPrefixKey {
                name: event.name,
                rule_idx: 0,
            },
        };

        // Get binary name
        let binary_name = fill_name_map!(KERNELMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(KERNELMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(KERNELMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            bpf_id.rule_idx = idx as u32;
            bpf_prog_type.rule_idx = idx as u32;
            bpf_name.rule_idx = idx as u8;
            bpf_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &KERNELMON_BPF_PROG_BINNAME_MAP,
                &KERNELMON_BPF_PROG_BINPATH_MAP,
                &KERNELMON_BPF_PROG_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(BpfProgFilter::new(
                    &KERNELMON_BPF_PROG_ID_MAP,
                    &KERNELMON_BPF_PROG_TYPE_MAP,
                    &KERNELMON_BPF_PROG_NAME_MAP,
                    &KERNELMON_BPF_PROG_PREFIX_MAP,
                    &bpf_id,
                    &bpf_prog_type,
                    &bpf_name,
                    &bpf_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            } else if let Some(deny_list) = sandbox
                && !deny_list
            {
                // allow list is not satisfied: send event
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                msg.blocked = true;
                return Ok(-1);
            }
        }
    }
    Err(0)
}

// Bpf prog rules maps
#[map]
static KERNELMON_BPF_PROG_LOAD_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Bpf prog maps begin
#[map]
// ID is not assigned to bpf program at loading time, so we cannot filter by it
static KERNELMON_BPF_PROG_LOAD_STUB_ID_MAP: HashMap<BpfIdKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_TYPE_MAP: HashMap<BpfProgTypeKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_NAME_MAP: HashMap<BpfNameKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_PREFIX_MAP: LpmTrie<BpfPrefixKey, u8> =
    LpmTrie::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_BINPATH_MAP: HashMap<PathMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_BINNAME_MAP: HashMap<FileNameMapKey, u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static KERNELMON_BPF_PROG_LOAD_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

// For 6.9 kernel and later we use bpf_prog_load
#[lsm(hook = "bpf_prog_load")]
pub fn bpf_prog_load_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_KERNEL, true, try_bpf_prog_load)
}

fn try_bpf_prog_load(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Kernel(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = KERNELMON_BPF_PROG_LOAD_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut KernelEventVariant as *mut u8;
        *p = KernelEventNumber::BpfProgLoad as u8;
    }
    let KernelEventVariant::BpfProgLoad(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let bpf_prog: *const bpf_prog = ctx.arg(0);
        if is_null_pointer(bpf_prog) {
            return Err(0);
        }
        if is_null_pointer((*bpf_prog).aux) {
            return Err(0);
        }
        event.prog_type = core::mem::transmute::<u32, BpfProgType>((*bpf_prog).type_);
        bpf_probe_read_kernel_str_bytes(
            (*(*bpf_prog).aux).name.as_ptr() as *const u8,
            &mut event.name,
        )
        .map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = KERNELMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };

        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[KernelEventNumber::BpfMapAccess as usize];

        // Get filtering attributes
        // Stub bpf prog id
        let mut bpf_id = BpfIdKey {
            rule_idx: 0,
            value: 0,
        };

        // Get bpf map type
        let mut bpf_prog_type = BpfProgTypeKey {
            rule_idx: 0,
            prog_type: event.prog_type,
        };

        // Get bpf map name
        let mut bpf_name = BpfNameKey {
            rule_idx: 0,
            name: event.name,
        };

        let mut bpf_prefix = Key {
            prefix_len: (MAX_BPFNAME_SIZE * 8) as u32,
            data: BpfPrefixKey {
                name: event.name,
                rule_idx: 0,
            },
        };

        // Get binary name
        let binary_name = fill_name_map!(KERNELMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(KERNELMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(KERNELMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            bpf_id.rule_idx = idx as u32;
            bpf_prog_type.rule_idx = idx as u32;
            bpf_name.rule_idx = idx as u8;
            bpf_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &KERNELMON_BPF_PROG_LOAD_BINNAME_MAP,
                &KERNELMON_BPF_PROG_LOAD_BINPATH_MAP,
                &KERNELMON_BPF_PROG_LOAD_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(BpfProgFilter::new(
                    &KERNELMON_BPF_PROG_LOAD_STUB_ID_MAP,
                    &KERNELMON_BPF_PROG_LOAD_TYPE_MAP,
                    &KERNELMON_BPF_PROG_LOAD_NAME_MAP,
                    &KERNELMON_BPF_PROG_LOAD_PREFIX_MAP,
                    &bpf_id,
                    &bpf_prog_type,
                    &bpf_name,
                    &bpf_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            } else if let Some(deny_list) = sandbox
                && !deny_list
            {
                // allow list is not satisfied: send event
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                msg.blocked = true;
                return Ok(-1);
            }
        }
    }
    Err(0)
}

// For 6.8 kernel and earlier we use security_bpf because security_bpf_prog_alloc does not provide any useful information compared to bpf_prog_load
#[lsm(hook = "bpf")]
pub fn bpf_prog_old_load_capture(ctx: LsmContext) -> i32 {
    // Using bpf hook only for
    unsafe {
        let cmd: u32 = ctx.arg(0);
        if cmd != BPF_PROG_LOAD {
            return 0;
        }
    }

    event_capture!(ctx, MSG_KERNEL, true, try_bpf_prog_old_load)
}

fn try_bpf_prog_old_load(ctx: LsmContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Kernel(ref mut msg) = generic_event.event else {
        return Err(0);
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = KERNELMON_BPF_PROG_LOAD_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut KernelEventVariant as *mut u8;
        *p = KernelEventNumber::BpfProgLoad as u8;
    }
    let KernelEventVariant::BpfProgLoad(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let prog_attr: *const bpf_attr__bindgen_ty_4 = ctx.arg(1);
        if is_null_pointer(prog_attr) {
            return Err(0);
        }
        let prog_type = (*prog_attr).prog_type;
        event.prog_type = core::mem::transmute::<u32, BpfProgType>(core::cmp::min(
            prog_type,
            BpfProgType::__MAX_BPF_PROG_TYPE as u32,
        ));
        bpf_probe_read_kernel_str_bytes(
            (*prog_attr).prog_name.as_ptr() as *const u8,
            &mut event.name,
        )
        .map_err(|_| 0i32)?;

        let Some(ref rule_array) = rules.0 else {
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        let Some(config_ptr) = KERNELMON_CONFIG.get_ptr(0) else {
            return Err(0);
        };

        let config = config_ptr.as_ref();
        let Some(config) = config else {
            return Err(0);
        };

        let sandbox: Option<bool> = config.sandbox_mode[KernelEventNumber::BpfMapAccess as usize];

        // Get filtering attributes
        // Stub bpf prog id
        let mut bpf_id = BpfIdKey {
            rule_idx: 0,
            value: 0,
        };

        // Get bpf map type
        let mut bpf_prog_type = BpfProgTypeKey {
            rule_idx: 0,
            prog_type: event.prog_type,
        };

        // Get bpf map name
        let mut bpf_name = BpfNameKey {
            rule_idx: 0,
            name: event.name,
        };

        let mut bpf_prefix = Key {
            prefix_len: (MAX_BPFNAME_SIZE * 8) as u32,
            data: BpfPrefixKey {
                name: event.name,
                rule_idx: 0,
            },
        };

        // Get binary name
        let binary_name = fill_name_map!(KERNELMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(KERNELMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(KERNELMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);
        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            bpf_id.rule_idx = idx as u32;
            bpf_prog_type.rule_idx = idx as u32;
            bpf_name.rule_idx = idx as u8;
            bpf_prefix.data.rule_idx = idx as u8;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &KERNELMON_BPF_PROG_LOAD_BINNAME_MAP,
                &KERNELMON_BPF_PROG_LOAD_BINPATH_MAP,
                &KERNELMON_BPF_PROG_LOAD_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(BpfProgFilter::new(
                    &KERNELMON_BPF_PROG_LOAD_STUB_ID_MAP,
                    &KERNELMON_BPF_PROG_LOAD_TYPE_MAP,
                    &KERNELMON_BPF_PROG_LOAD_NAME_MAP,
                    &KERNELMON_BPF_PROG_LOAD_PREFIX_MAP,
                    &bpf_id,
                    &bpf_prog_type,
                    &bpf_name,
                    &bpf_prefix,
                ))?;
                let passed = event_filter.check_predicate(&rule.event)?;
                if passed {
                    if sandbox.is_none() {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        return Ok(0);
                    }
                    let deny_list = sandbox.unwrap();
                    if deny_list {
                        enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                        msg.blocked = true;
                        return Ok(-1);
                    }
                    // allow list is satisfied: do not send event
                    return Err(0);
                } else if let Some(deny_list) = sandbox
                    && !deny_list
                {
                    // allow list is not satisfied: send event
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    msg.blocked = true;
                    return Ok(-1);
                }
            } else if let Some(deny_list) = sandbox
                && !deny_list
            {
                // allow list is not satisfied: send event
                enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                msg.blocked = true;
                return Ok(-1);
            }
        }
    }
    Err(0)
}

#[inline(always)]
fn enrich_with_proc_info_and_rule_idx(msg: &mut KernelMsg, proc: &ProcInfo, rule_idx: Option<u8>) {
    msg.rule_idx = rule_idx;

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
