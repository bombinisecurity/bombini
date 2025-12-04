#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    cty::c_void,
    helpers::{bpf_get_socket_cookie, bpf_probe_read_kernel_buf},
    macros::{fexit, map},
    maps::{
        array::Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::LpmTrie,
    },
    programs::FExitContext,
};

use bombini_detectors_ebpf::{
    filter::ip::{Ipv4Filter, Ipv6Filter},
    vmlinux::sock,
};

use bombini_common::config::network::{Config, IpFilterMask};
use bombini_common::event::{
    Event, GenericEvent, MSG_NETWORK, network::TcpConnectionV4, network::TcpConnectionV6,
    process::ProcInfo,
};
use bombini_common::{
    constants::{MAX_FILE_PATH, MAX_FILE_PREFIX, MAX_FILENAME_SIZE},
    event::network::NetworkEventVariant,
};

use bombini_detectors_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
};

/// Holds current alive processes
#[map]
static PROCMON_PROC_MAP: LruHashMap<u32, ProcInfo> = LruHashMap::pinned(1, 0);

#[map]
static NETMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static NETMON_SOCK_COOKIE_MAP: LruHashMap<u64, u8> = LruHashMap::with_max_entries(512, 0);

// Filter maps

// It's better to use BPF_MAP_TYPE_ARRAY_OF_MAPS when https://github.com/aya-rs/aya/pull/70
// will be merged. We can have array of maps to set separate process filters for ingress/egress
// connections.

#[map]
static NETMON_FILTER_UID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_EUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_AUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_BINNAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_BINPREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

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

fn parse_v6_sock(event: &mut TcpConnectionV6, s: *const sock) -> Result<(), u32> {
    unsafe {
        let skport_pair = (*s).__sk_common.__bindgen_anon_3.skc_portpair;
        bpf_probe_read_kernel_buf(
            &(*s).__sk_common.skc_v6_daddr.in6_u.u6_addr8 as *const _,
            &mut event.daddr,
        )
        .map_err(|_| 0u32)?;
        bpf_probe_read_kernel_buf(
            &(*s).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 as *const _,
            &mut event.saddr,
        )
        .map_err(|_| 0u32)?;
        event.sport = (skport_pair >> 16) as u16;
        event.dport = skport_pair as u16;
        event.dport = event.dport.rotate_left(8);
        event.cookie = bpf_get_socket_cookie(s as *mut sock as *mut c_void);
    }
    Ok(())
}

#[map]
static NETMON_FILTER_SRC_IP4_EGRESS_MAP: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_DST_IP4_EGRESS_MAP: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1, 0);

#[fexit(function = "tcp_v4_connect")]
pub fn tcp_v4_connect_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_v4_connect)
}

fn try_tcp_v4_connect(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    if proc.start == 0 {
        return Err(0);
    }

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &NETMON_FILTER_UID_MAP,
            &NETMON_FILTER_EUID_MAP,
            &NETMON_FILTER_AUID_MAP,
            &NETMON_FILTER_BINNAME_MAP,
            &NETMON_FILTER_BINPATH_MAP,
            &NETMON_FILTER_BINPREFIX_MAP,
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
    unsafe {
        let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
        // TcpConV4Established
        *p = 0;
    }

    let NetworkEventVariant::TcpConV4Establish(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v4_sock(event, s);
    }
    if event.saddr == 0 || event.daddr == 0 || event.sport == 0 || event.dport == 0 {
        return Err(0);
    }
    // Filter Ipv4 egress connections
    if config.ip_filter_mask.intersects(
        IpFilterMask::DEST_IP4_EGRESS_ALLOW
            | IpFilterMask::DEST_IP4_EGRESS_DENY
            | IpFilterMask::SOURCE_IP4_EGRESS_ALLOW
            | IpFilterMask::SOURCE_IP4_EGRESS_DENY,
    ) {
        let ip_filter = Ipv4Filter::new(
            &NETMON_FILTER_SRC_IP4_EGRESS_MAP,
            &NETMON_FILTER_DST_IP4_EGRESS_MAP,
        );
        let saddr = event.saddr.to_le_bytes();
        let daddr = event.daddr.to_le_bytes();
        if !ip_filter.filter(config.ip_filter_mask, &saddr, &daddr) {
            return Err(0);
        }
    }

    util::process_key_init(&mut msg.process, proc);
    let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &0, 0);
    Ok(0)
}

#[map]
static NETMON_FILTER_SRC_IP6_EGRESS_MAP: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_DST_IP6_EGRESS_MAP: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1, 0);

#[fexit(function = "tcp_v6_connect")]
pub fn tcp_v6_connect_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_v6_connect)
}

fn try_tcp_v6_connect(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    if proc.start == 0 {
        return Err(0);
    }

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &NETMON_FILTER_UID_MAP,
            &NETMON_FILTER_EUID_MAP,
            &NETMON_FILTER_AUID_MAP,
            &NETMON_FILTER_BINNAME_MAP,
            &NETMON_FILTER_BINPATH_MAP,
            &NETMON_FILTER_BINPREFIX_MAP,
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

    unsafe {
        let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
        // TcpConV6Established
        *p = 1;
    }

    let NetworkEventVariant::TcpConV6Establish(ref mut event) = msg.event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v6_sock(event, s)?;
    }
    if event.sport == 0 || event.dport == 0 {
        return Err(0);
    }

    // Filter Ipv6 egress connections
    if config.ip_filter_mask.intersects(
        IpFilterMask::DEST_IP6_EGRESS_ALLOW
            | IpFilterMask::DEST_IP6_EGRESS_DENY
            | IpFilterMask::SOURCE_IP6_EGRESS_ALLOW
            | IpFilterMask::SOURCE_IP6_EGRESS_DENY,
    ) {
        let ip_filter = Ipv6Filter::new(
            &NETMON_FILTER_SRC_IP6_EGRESS_MAP,
            &NETMON_FILTER_DST_IP6_EGRESS_MAP,
        );
        if !ip_filter.filter(config.ip_filter_mask, &event.saddr, &event.daddr) {
            return Err(0);
        }
    }

    util::process_key_init(&mut msg.process, proc);
    let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &0, 0);
    Ok(0)
}

#[fexit(function = "tcp_close")]
pub fn tcp_close_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_close)
}

fn try_tcp_close(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &NETMON_FILTER_UID_MAP,
            &NETMON_FILTER_EUID_MAP,
            &NETMON_FILTER_AUID_MAP,
            &NETMON_FILTER_BINNAME_MAP,
            &NETMON_FILTER_BINPATH_MAP,
            &NETMON_FILTER_BINPREFIX_MAP,
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

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;
        match family {
            AF_INET => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                // TcpConV4Closed
                *p = 2;
                let NetworkEventVariant::TcpConV4Close(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v4_sock(event, s);
                if NETMON_SOCK_COOKIE_MAP.get_ptr(&event.cookie).is_none() {
                    return Err(0);
                }
                // Filter Ipv4 connections
                if config.ip_filter_mask.intersects(
                    IpFilterMask::DEST_IP4_EGRESS_ALLOW
                        | IpFilterMask::DEST_IP4_EGRESS_DENY
                        | IpFilterMask::SOURCE_IP4_EGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP4_EGRESS_DENY
                        | IpFilterMask::DEST_IP4_INGRESS_ALLOW
                        | IpFilterMask::DEST_IP4_INGRESS_DENY
                        | IpFilterMask::SOURCE_IP4_INGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP4_INGRESS_DENY,
                ) {
                    let ip_filter = Ipv4Filter::new(
                        &NETMON_FILTER_SRC_IP4_EGRESS_MAP,
                        &NETMON_FILTER_DST_IP4_EGRESS_MAP,
                    );
                    let saddr = event.saddr.to_le_bytes();
                    let daddr = event.daddr.to_le_bytes();
                    if !ip_filter.filter(config.ip_filter_mask, &saddr, &daddr) {
                        return Err(0);
                    }
                }

                util::process_key_init(&mut msg.process, proc);
                let _ = NETMON_SOCK_COOKIE_MAP.remove(&event.cookie);
                Ok(0)
            }
            AF_INET6 => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                // TcpConV6Closed
                *p = 3;
                let NetworkEventVariant::TcpConV6Close(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v6_sock(event, s)?;
                if NETMON_SOCK_COOKIE_MAP.get_ptr(&event.cookie).is_none() {
                    return Err(0);
                }

                // Filter Ipv6 connections
                if config.ip_filter_mask.intersects(
                    IpFilterMask::DEST_IP6_EGRESS_ALLOW
                        | IpFilterMask::DEST_IP6_EGRESS_DENY
                        | IpFilterMask::SOURCE_IP6_EGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP6_EGRESS_DENY
                        | IpFilterMask::DEST_IP6_INGRESS_ALLOW
                        | IpFilterMask::DEST_IP6_INGRESS_DENY
                        | IpFilterMask::SOURCE_IP6_INGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP6_INGRESS_DENY,
                ) {
                    let ip_filter = Ipv6Filter::new(
                        &NETMON_FILTER_SRC_IP6_EGRESS_MAP,
                        &NETMON_FILTER_DST_IP6_EGRESS_MAP,
                    );
                    if !ip_filter.filter(config.ip_filter_mask, &event.saddr, &event.daddr) {
                        return Err(0);
                    }
                }

                util::process_key_init(&mut msg.process, proc);
                let _ = NETMON_SOCK_COOKIE_MAP.remove(&event.cookie);
                Ok(0)
            }
            _ => Err(0),
        }
    }
}

#[map]
static NETMON_FILTER_SRC_IP4_INGRESS_MAP: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_DST_IP4_INGRESS_MAP: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_SRC_IP6_INGRESS_MAP: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1, 0);

#[map]
static NETMON_FILTER_DST_IP6_INGRESS_MAP: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1, 0);

#[fexit(function = "inet_csk_accept")]
pub fn inet_csk_accept_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_inet_csk_accept)
}

fn try_inet_csk_accept(ctx: FExitContext, generic_event: &mut GenericEvent) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(ref mut msg) = generic_event.event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    if proc.start == 0 {
        return Err(0);
    }

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &NETMON_FILTER_UID_MAP,
            &NETMON_FILTER_EUID_MAP,
            &NETMON_FILTER_AUID_MAP,
            &NETMON_FILTER_BINNAME_MAP,
            &NETMON_FILTER_BINPATH_MAP,
            &NETMON_FILTER_BINPREFIX_MAP,
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

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;
        match family {
            AF_INET => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                // TcpConV6Accepted
                *p = 4;
                let NetworkEventVariant::TcpConV4Accept(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v4_sock(event, s);
                if event.sport == 0 && event.dport == 0 {
                    return Err(0);
                }

                // Filter Ipv4 ingress connections
                if config.ip_filter_mask.intersects(
                    IpFilterMask::DEST_IP4_INGRESS_ALLOW
                        | IpFilterMask::DEST_IP4_INGRESS_DENY
                        | IpFilterMask::SOURCE_IP4_INGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP4_INGRESS_DENY,
                ) {
                    let ip_filter = Ipv4Filter::new(
                        &NETMON_FILTER_SRC_IP4_INGRESS_MAP,
                        &NETMON_FILTER_DST_IP4_INGRESS_MAP,
                    );
                    let saddr = event.saddr.to_le_bytes();
                    let daddr = event.daddr.to_le_bytes();
                    if !ip_filter.filter(config.ip_filter_mask, &saddr, &daddr) {
                        return Err(0);
                    }
                }

                util::process_key_init(&mut msg.process, proc);
                let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &0, 0);
                Ok(0)
            }
            AF_INET6 => {
                let p = &mut msg.event as *mut NetworkEventVariant as *mut u8;
                // TcpConV6Accepted
                *p = 5;
                let NetworkEventVariant::TcpConV6Accept(ref mut event) = msg.event else {
                    return Err(0);
                };
                parse_v6_sock(event, s)?;
                if event.sport == 0 && event.dport == 0 {
                    return Err(0);
                }

                // Filter Ipv6 ingress connections
                if config.ip_filter_mask.intersects(
                    IpFilterMask::DEST_IP6_INGRESS_ALLOW
                        | IpFilterMask::DEST_IP6_INGRESS_DENY
                        | IpFilterMask::SOURCE_IP6_INGRESS_ALLOW
                        | IpFilterMask::SOURCE_IP6_INGRESS_DENY,
                ) {
                    let ip_filter = Ipv6Filter::new(
                        &NETMON_FILTER_SRC_IP6_INGRESS_MAP,
                        &NETMON_FILTER_DST_IP6_INGRESS_MAP,
                    );
                    if !ip_filter.filter(config.ip_filter_mask, &event.saddr, &event.daddr) {
                        return Err(0);
                    }
                }

                util::process_key_init(&mut msg.process, proc);
                let _ = NETMON_SOCK_COOKIE_MAP.insert(&event.cookie, &0, 0);
                Ok(0)
            }
            _ => Err(0),
        }
    }
}
