#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::bpf_dynptr,
    cty::c_void,
    helpers::{
        bpf_get_socket_cookie, bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
        r#gen::{bpf_dynptr_from_mem, bpf_dynptr_write},
    },
    macros::{fexit, map},
    maps::{
        LpmTrie, LruHashMap, array::Array, hash_map::HashMap, lpm_trie::Key,
        per_cpu_array::PerCpuArray,
    },
    programs::FExitContext,
};

use bombini_detectors_ebpf::vmlinux::sock;

use bombini_common::event::{
    Event, GenericEvent, MSG_NETWORK,
    network::{NetworkMsg, TcpConnectionV4, TcpConnectionV6},
    process::ProcInfo,
};
use bombini_common::{
    config::rule::{
        FileNameMapKey, Ipv4MapKey, Ipv6MapKey, PathMapKey, PathPrefixMapKey, PortKey, Rules,
    },
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::network::{NetworkEventNumber, NetworkEventVariant},
};

use bombini_detectors_ebpf::{
    event_capture,
    event_map::rb_event_init,
    filter::{
        netmon::ip::{Ipv4Filter, Ipv6Filter},
        scope::ScopeFilter,
    },
    interpreter::{self, rule::IsEmpty},
    util,
};

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Direction {
    Ingress = 0,
    Egress,
}

#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static NETMON_SOCK_COOKIE_MAP: LruHashMap<u64, u8> = LruHashMap::with_max_entries(512, 0);

// Helpers
#[map]
static ZERO_PATH_MAP: Array<[u8; MAX_FILE_PATH]> = Array::with_max_entries(1, 0);

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
            .map_err(|_| 0i32)?;
        prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
        prefix
    }};
}

macro_rules! fill_ip_map {
    ($map:ident, $src:expr, $addr_size:literal) => {{
        let Some(ip) = $map.get_ptr_mut(0) else {
            return Err(0);
        };
        let ip = ip.as_mut();
        let Some(ip) = ip else {
            return Err(0);
        };
        let Some(zero_ptr) = ZERO_PATH_MAP.get_ptr_mut(0) else {
            return Err(0);
        };
        let mut tmp = bpf_dynptr { __opaque: [0, 0] };
        bpf_dynptr_from_mem(
            ip.data.ip_addr.as_mut_ptr() as *mut u8 as *mut _,
            core::mem::size_of_val(&ip.data.ip_addr) as u32,
            0,
            &mut tmp as *mut _,
        );
        bpf_dynptr_write(
            &tmp as *const _,
            0,
            zero_ptr as *mut _,
            core::mem::size_of_val(&ip.data.ip_addr) as u32,
            0,
        );
        bpf_probe_read_kernel_buf($src as *const u8, &mut ip.data.ip_addr).map_err(|_| 0i32)?;
        ip.prefix_len = (($addr_size + 1) * 8) as u32;
        ip
    }};
}

// Rules maps
#[map]
static NETMON_EGRESS_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_RULE_MAP: Array<Rules> = Array::with_max_entries(1, 0);

// Attribute helper maps begin
#[map]
static NETMON_BINARY_PATH_MAP: PerCpuArray<PathMapKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_BINARY_FILE_NAME_MAP: PerCpuArray<FileNameMapKey> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_BINARY_PATH_PREFIX_MAP: PerCpuArray<Key<PathPrefixMapKey>> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_IPV4_SRC_MAP: PerCpuArray<Key<Ipv4MapKey>> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_IPV4_DST_MAP: PerCpuArray<Key<Ipv4MapKey>> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_IPV6_SRC_MAP: PerCpuArray<Key<Ipv6MapKey>> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETMON_IPV6_DST_MAP: PerCpuArray<Key<Ipv6MapKey>> = PerCpuArray::with_max_entries(1, 0);
// helper maps end

// Attribute filter maps begin
#[map]
static NETMON_EGRESS_SRC_IPV6_MAP: LpmTrie<Ipv6MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_DST_IPV6_MAP: LpmTrie<Ipv6MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_SRC_IPV4_MAP: LpmTrie<Ipv4MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_DST_IPV4_MAP: LpmTrie<Ipv4MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_SRC_PORT_MAP: HashMap<PortKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_DST_PORT_MAP: HashMap<PortKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_EGRESS_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_SRC_IPV6_MAP: LpmTrie<Ipv6MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_DST_IPV6_MAP: LpmTrie<Ipv6MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_SRC_IPV4_MAP: LpmTrie<Ipv4MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_DST_IPV4_MAP: LpmTrie<Ipv4MapKey, u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_SRC_PORT_MAP: HashMap<PortKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_DST_PORT_MAP: HashMap<PortKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_BINPATH_MAP: HashMap<PathMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_BINNAME_MAP: HashMap<FileNameMapKey, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_INGRESS_BINPREFIX_MAP: LpmTrie<PathPrefixMapKey, u8> =
    LpmTrie::with_max_entries(1, 0);
// Filter maps end

const AF_INET6: u16 = 10;

const AF_INET: u16 = 2;

fn parse_v4_sock(event: &mut TcpConnectionV4, s: *const sock) {
    unsafe {
        let skaddr_pair = (*s).__sk_common.__bindgen_anon_1.skc_addrpair;
        let skport_pair = (*s).__sk_common.__bindgen_anon_3.skc_portpair;
        event.saddr = (skaddr_pair >> 32) as u32;
        event.daddr = skaddr_pair as u32;
        event.sport = (skport_pair >> 16) as u16;
        event.dport = skport_pair as u16;
        event.dport = event.dport.rotate_left(8);
        event.cookie = bpf_get_socket_cookie(s as *mut sock as *mut c_void);
    }
}

fn parse_v6_sock(event: &mut TcpConnectionV6, s: *const sock) -> Result<(), i32> {
    unsafe {
        let skport_pair = (*s).__sk_common.__bindgen_anon_3.skc_portpair;
        bpf_probe_read_kernel_buf(
            &(*s).__sk_common.skc_v6_daddr.in6_u.u6_addr8 as *const _,
            &mut event.daddr,
        )
        .map_err(|_| 0i32)?;
        bpf_probe_read_kernel_buf(
            &(*s).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 as *const _,
            &mut event.saddr,
        )
        .map_err(|_| 0i32)?;
        event.sport = (skport_pair >> 16) as u16;
        event.dport = skport_pair as u16;
        event.dport = event.dport.rotate_left(8);
        event.cookie = bpf_get_socket_cookie(s as *mut sock as *mut c_void);
    }
    Ok(())
}

#[fexit(function = "tcp_v4_connect")]
pub fn tcp_v4_connect(ctx: FExitContext) -> i32 {
    event_capture!(ctx, MSG_NETWORK, true, try_tcp_v4_connect)
}

fn try_tcp_v4_connect(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = NETMON_EGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
        *p = NetworkEventNumber::TcpConV4Establish as u8;
    }

    let NetworkEventVariant::TcpConV4Establish(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v4_sock(event, s);

        if event.saddr == 0 || event.daddr == 0 || event.sport == 0 || event.dport == 0 {
            return Err(0);
        }

        let Some(ref rule_array) = rules.0 else {
            let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &(Direction::Egress as u8), 0);
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        // Get binary name
        let binary_name = fill_name_map!(NETMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(NETMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(NETMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        // Get ip_src
        let saddr = event.saddr.to_le_bytes();
        let ip_src = fill_ip_map!(NETMON_IPV4_SRC_MAP, &saddr, 4);

        // Get ip_dst
        let daddr = event.daddr.to_le_bytes();
        let ip_dst = fill_ip_map!(NETMON_IPV4_DST_MAP, &daddr, 4);

        // Get port_src
        let mut port_src = PortKey {
            rule_idx: 0,
            port: event.sport,
        };

        // Get port_dst
        let mut port_dst = PortKey {
            rule_idx: 0,
            port: event.dport,
        };

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            ip_src.data.rule_idx = idx as u8;
            ip_dst.data.rule_idx = idx as u8;
            port_src.rule_idx = idx as u16;
            port_dst.rule_idx = idx as u16;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &NETMON_EGRESS_BINNAME_MAP,
                &NETMON_EGRESS_BINPATH_MAP,
                &NETMON_EGRESS_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(Ipv4Filter::new(
                    &NETMON_EGRESS_SRC_IPV4_MAP,
                    &NETMON_EGRESS_DST_IPV4_MAP,
                    &NETMON_EGRESS_SRC_PORT_MAP,
                    &NETMON_EGRESS_DST_PORT_MAP,
                    ip_src,
                    ip_dst,
                    &port_src,
                    &port_dst,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    let _ =
                        NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &(Direction::Egress as u8), 0);
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    return Ok(0);
                }
            }
        }
    }
    Err(0)
}

#[fexit(function = "tcp_v6_connect")]
pub fn tcp_v6_connect(ctx: FExitContext) -> i32 {
    event_capture!(ctx, MSG_NETWORK, true, try_tcp_v6_connect)
}

fn try_tcp_v6_connect(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = NETMON_EGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
        *p = NetworkEventNumber::TcpConV6Establish as u8;
    }

    let NetworkEventVariant::TcpConV6Establish(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v6_sock(event, s)?;

        if event.sport == 0 || event.dport == 0 {
            return Err(0);
        }

        let Some(ref rule_array) = rules.0 else {
            let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &(Direction::Egress as u8), 0);
            enrich_with_proc_info_and_rule_idx(msg, proc, None);
            return Ok(0);
        };

        // Get binary name
        let binary_name = fill_name_map!(NETMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(NETMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(NETMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        // Get ip_src
        let ip_src = fill_ip_map!(NETMON_IPV6_SRC_MAP, &event.saddr, 16);

        // Get ip_dst
        let ip_dst = fill_ip_map!(NETMON_IPV6_DST_MAP, &event.daddr, 16);

        // Get port_src
        let mut port_src = PortKey {
            rule_idx: 0,
            port: event.sport,
        };

        // Get port_dst
        let mut port_dst = PortKey {
            rule_idx: 0,
            port: event.dport,
        };

        for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
            ip_src.data.rule_idx = idx as u8;
            ip_dst.data.rule_idx = idx as u8;
            port_src.rule_idx = idx as u16;
            port_dst.rule_idx = idx as u16;
            binary_name.rule_idx = idx as u8;
            binary_path.rule_idx = idx as u8;
            binary_prefix.data.rule_idx = idx as u8;
            let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                &NETMON_EGRESS_BINNAME_MAP,
                &NETMON_EGRESS_BINPATH_MAP,
                &NETMON_EGRESS_BINPREFIX_MAP,
                binary_name,
                binary_path,
                binary_prefix,
            ))?;
            if scope_filter.check_predicate(&rule.scope)? {
                let mut event_filter = interpreter::Interpreter::new(Ipv6Filter::new(
                    &NETMON_EGRESS_SRC_IPV6_MAP,
                    &NETMON_EGRESS_DST_IPV6_MAP,
                    &NETMON_EGRESS_SRC_PORT_MAP,
                    &NETMON_EGRESS_DST_PORT_MAP,
                    ip_src,
                    ip_dst,
                    &port_src,
                    &port_dst,
                ))?;
                if event_filter.check_predicate(&rule.event)? {
                    let _ =
                        NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &(Direction::Egress as u8), 0);
                    enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                    return Ok(0);
                }
            }
        }
    }
    Err(0)
}

#[fexit(function = "tcp_close")]
pub fn tcp_close_v4(ctx: FExitContext) -> i32 {
    event_capture!(ctx, MSG_NETWORK, true, try_tcp_close_v4)
}

fn try_tcp_close_v4(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules_ingress) = NETMON_INGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    let Some(rules_egress) = NETMON_EGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;

        if family == AF_INET {
            // Get binary name
            let binary_name = fill_name_map!(NETMON_BINARY_FILE_NAME_MAP, &proc.filename);

            // Get binary path
            let binary_path = fill_path_map!(NETMON_BINARY_PATH_MAP, &proc.binary_path);

            // Get binary prefix
            let binary_prefix = fill_prefix_map!(NETMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

            let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
            *p = NetworkEventNumber::TcpConV4Close as u8;
            let NetworkEventVariant::TcpConV4Close(ref mut event) = msg.event else {
                return Err(0);
            };
            parse_v4_sock(event, s);
            let Some(direction) = NETMON_SOCK_COOKIE_MAP.get(&event.cookie) else {
                return Err(0);
            };
            let direction = *direction;
            let _ = NETMON_SOCK_COOKIE_MAP.remove(&event.cookie);

            if rules_egress.0.is_none() && rules_ingress.0.is_none() {
                enrich_with_proc_info_and_rule_idx(msg, proc, None);
                return Ok(0);
            }

            // Get ip_src
            let saddr = event.saddr.to_le_bytes();
            let ip_src = fill_ip_map!(NETMON_IPV4_SRC_MAP, &saddr, 4);

            // Get ip_dst
            let daddr = event.daddr.to_le_bytes();
            let ip_dst = fill_ip_map!(NETMON_IPV4_DST_MAP, &daddr, 4);

            // Get port_src
            let mut port_src = PortKey {
                rule_idx: 0,
                port: event.sport,
            };

            // Get port_dst
            let mut port_dst = PortKey {
                rule_idx: 0,
                port: event.dport,
            };

            if direction == Direction::Ingress as u8
                && let Some(ref rule_array) = rules_ingress.0
            {
                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_INGRESS_BINNAME_MAP,
                        &NETMON_INGRESS_BINPATH_MAP,
                        &NETMON_INGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv4Filter::new(
                            &NETMON_INGRESS_SRC_IPV4_MAP,
                            &NETMON_INGRESS_DST_IPV4_MAP,
                            &NETMON_INGRESS_SRC_PORT_MAP,
                            &NETMON_INGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }
            } else if direction == Direction::Egress as u8
                && let Some(ref rule_array) = rules_egress.0
            {
                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_EGRESS_BINNAME_MAP,
                        &NETMON_EGRESS_BINPATH_MAP,
                        &NETMON_EGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv4Filter::new(
                            &NETMON_EGRESS_SRC_IPV4_MAP,
                            &NETMON_EGRESS_DST_IPV4_MAP,
                            &NETMON_EGRESS_SRC_PORT_MAP,
                            &NETMON_EGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }
            }
        }
    }
    Err(0)
}

#[fexit(function = "tcp_close")]
pub fn tcp_close_v6(ctx: FExitContext) -> i32 {
    event_capture!(ctx, MSG_NETWORK, true, try_tcp_close_v6)
}

fn try_tcp_close_v6(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules_ingress) = NETMON_INGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    let Some(rules_egress) = NETMON_EGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;

        if family == AF_INET6 {
            // Get binary name
            let binary_name = fill_name_map!(NETMON_BINARY_FILE_NAME_MAP, &proc.filename);

            // Get binary path
            let binary_path = fill_path_map!(NETMON_BINARY_PATH_MAP, &proc.binary_path);

            // Get binary prefix
            let binary_prefix = fill_prefix_map!(NETMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

            let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
            *p = NetworkEventNumber::TcpConV6Close as u8;
            let NetworkEventVariant::TcpConV6Close(ref mut event) = msg.event else {
                return Err(0);
            };
            parse_v6_sock(event, s)?;
            let Some(direction) = NETMON_SOCK_COOKIE_MAP.get(&event.cookie) else {
                return Err(0);
            };
            let direction = *direction;
            let _ = NETMON_SOCK_COOKIE_MAP.remove(&event.cookie);

            if rules_egress.0.is_none() && rules_ingress.0.is_none() {
                enrich_with_proc_info_and_rule_idx(msg, proc, None);
                return Ok(0);
            }

            // Get ip_src
            let ip_src = fill_ip_map!(NETMON_IPV6_SRC_MAP, &event.saddr, 16);

            // Get ip_dst
            let ip_dst = fill_ip_map!(NETMON_IPV6_DST_MAP, &event.daddr, 16);

            // Get port_src
            let mut port_src = PortKey {
                rule_idx: 0,
                port: event.sport,
            };

            // Get port_dst
            let mut port_dst = PortKey {
                rule_idx: 0,
                port: event.dport,
            };

            if direction == Direction::Ingress as u8
                && let Some(ref rule_array) = rules_ingress.0
            {
                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_INGRESS_BINNAME_MAP,
                        &NETMON_INGRESS_BINPATH_MAP,
                        &NETMON_INGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv6Filter::new(
                            &NETMON_INGRESS_SRC_IPV6_MAP,
                            &NETMON_INGRESS_DST_IPV6_MAP,
                            &NETMON_INGRESS_SRC_PORT_MAP,
                            &NETMON_INGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }
            } else if direction == Direction::Egress as u8
                && let Some(ref rule_array) = rules_egress.0
            {
                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_EGRESS_BINNAME_MAP,
                        &NETMON_EGRESS_BINPATH_MAP,
                        &NETMON_EGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv6Filter::new(
                            &NETMON_EGRESS_SRC_IPV6_MAP,
                            &NETMON_EGRESS_DST_IPV6_MAP,
                            &NETMON_EGRESS_SRC_PORT_MAP,
                            &NETMON_EGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }
            }
            return Err(0);
        }
    }
    Err(0)
}

#[fexit(function = "inet_csk_accept")]
pub fn inet_csk_accept(ctx: FExitContext) -> i32 {
    event_capture!(ctx, MSG_NETWORK, true, try_inet_csk_accept)
}

fn try_inet_csk_accept(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<i32, i32> {
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    let Some(rules) = NETMON_INGRESS_RULE_MAP.get(0) else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;

        // Get binary name
        let binary_name = fill_name_map!(NETMON_BINARY_FILE_NAME_MAP, &proc.filename);

        // Get binary path
        let binary_path = fill_path_map!(NETMON_BINARY_PATH_MAP, &proc.binary_path);

        // Get binary prefix
        let binary_prefix = fill_prefix_map!(NETMON_BINARY_PATH_PREFIX_MAP, &proc.binary_path);

        match family {
            AF_INET => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                *p = NetworkEventNumber::TcpConV4Accept as u8;
                let NetworkEventVariant::TcpConV4Accept(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v4_sock(event, s);
                if event.sport == 0 && event.dport == 0 {
                    return Err(0);
                }

                let Some(ref rule_array) = rules.0 else {
                    let _ = NETMON_SOCK_COOKIE_MAP.insert(
                        &event.cookie,
                        &(Direction::Ingress as u8),
                        0,
                    );
                    enrich_with_proc_info_and_rule_idx(msg, proc, None);
                    return Ok(0);
                };

                // Get ip_src
                let saddr = event.saddr.to_le_bytes();
                let ip_src = fill_ip_map!(NETMON_IPV4_SRC_MAP, &saddr, 4);

                // Get ip_dst
                let daddr = event.daddr.to_le_bytes();
                let ip_dst = fill_ip_map!(NETMON_IPV4_DST_MAP, &daddr, 4);

                // Get port_src
                let mut port_src = PortKey {
                    rule_idx: 0,
                    port: event.sport,
                };

                // Get port_dst
                let mut port_dst = PortKey {
                    rule_idx: 0,
                    port: event.dport,
                };

                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_INGRESS_BINNAME_MAP,
                        &NETMON_INGRESS_BINPATH_MAP,
                        &NETMON_INGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv4Filter::new(
                            &NETMON_INGRESS_SRC_IPV4_MAP,
                            &NETMON_INGRESS_DST_IPV4_MAP,
                            &NETMON_INGRESS_SRC_PORT_MAP,
                            &NETMON_INGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            let _ = NETMON_SOCK_COOKIE_MAP.insert(
                                &event.cookie,
                                &(Direction::Ingress as u8),
                                0,
                            );
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }
                Err(0)
            }
            AF_INET6 => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                *p = NetworkEventNumber::TcpConV6Accept as u8;
                let NetworkEventVariant::TcpConV6Accept(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v6_sock(event, s)?;
                if event.sport == 0 && event.dport == 0 {
                    return Err(0);
                }

                let Some(ref rule_array) = rules.0 else {
                    let _ = NETMON_SOCK_COOKIE_MAP.insert(
                        &event.cookie,
                        &(Direction::Ingress as u8),
                        0,
                    );
                    enrich_with_proc_info_and_rule_idx(msg, proc, None);
                    return Ok(0);
                };

                // Get ip_src
                let ip_src = fill_ip_map!(NETMON_IPV6_SRC_MAP, &event.saddr, 16);

                // Get ip_dst
                let ip_dst = fill_ip_map!(NETMON_IPV6_DST_MAP, &event.daddr, 16);

                // Get port_src
                let mut port_src = PortKey {
                    rule_idx: 0,
                    port: event.sport,
                };

                // Get port_dst
                let mut port_dst = PortKey {
                    rule_idx: 0,
                    port: event.dport,
                };

                for (idx, rule) in rule_array.iter().take_while(|x| !x.is_empty()).enumerate() {
                    ip_src.data.rule_idx = idx as u8;
                    ip_dst.data.rule_idx = idx as u8;
                    port_src.rule_idx = idx as u16;
                    port_dst.rule_idx = idx as u16;
                    binary_name.rule_idx = idx as u8;
                    binary_path.rule_idx = idx as u8;
                    binary_prefix.data.rule_idx = idx as u8;
                    let mut scope_filter = interpreter::Interpreter::new(ScopeFilter::new(
                        &NETMON_INGRESS_BINNAME_MAP,
                        &NETMON_INGRESS_BINPATH_MAP,
                        &NETMON_INGRESS_BINPREFIX_MAP,
                        binary_name,
                        binary_path,
                        binary_prefix,
                    ))?;
                    if scope_filter.check_predicate(&rule.scope)? {
                        let mut event_filter = interpreter::Interpreter::new(Ipv6Filter::new(
                            &NETMON_INGRESS_SRC_IPV6_MAP,
                            &NETMON_INGRESS_DST_IPV6_MAP,
                            &NETMON_INGRESS_SRC_PORT_MAP,
                            &NETMON_INGRESS_DST_PORT_MAP,
                            ip_src,
                            ip_dst,
                            &port_src,
                            &port_dst,
                        ))?;
                        if event_filter.check_predicate(&rule.event)? {
                            let _ = NETMON_SOCK_COOKIE_MAP.insert(
                                &event.cookie,
                                &(Direction::Ingress as u8),
                                0,
                            );
                            enrich_with_proc_info_and_rule_idx(msg, proc, Some(idx as u8));
                            return Ok(0);
                        }
                    }
                }

                Err(0)
            }
            _ => Err(0),
        }
    }
}

#[inline(always)]
fn enrich_with_proc_info_and_rule_idx(msg: &mut NetworkMsg, proc: &ProcInfo, rule_idx: Option<u8>) {
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
