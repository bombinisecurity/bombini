#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_socket_cookie, bpf_probe_read_kernel_buf},
    macros::{fexit, map},
    maps::{array::Array, hash_map::HashMap},
    programs::FExitContext,
    EbpfContext,
};

use bombini_detectors_ebpf::vmlinux::sock;

use bombini_common::event::{
    network::TcpConnectionV4, network::TcpConnectionV6, process::ProcInfo,
};
use bombini_common::event::{Event, MSG_NETWORK};
use bombini_common::{config::network::Config, event::network::NetworkMsg};

use bombini_detectors_ebpf::{event_capture, event_map::rb_event_init, util};

/// Holds current alive processes
#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);

#[map]
static NETMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const AF_INET6: u16 = 10;

const AF_INET: u16 = 2;

unsafe fn parse_v4_sock(event: &mut TcpConnectionV4, s: *const sock) {
    let skaddr_pair = (*s).__sk_common.__bindgen_anon_1.skc_addrpair;
    let skport_pair = (*s).__sk_common.__bindgen_anon_3.skc_portpair;
    event.saddr = (skaddr_pair >> 32) as u32;
    event.daddr = skaddr_pair as u32;
    event.sport = (skport_pair >> 16) as u16;
    event.dport = skport_pair as u16;
    event.dport = event.dport.rotate_left(8);
    event.cookie = bpf_get_socket_cookie(s as *mut sock as *mut c_void);
}

unsafe fn parse_v6_sock(event: &mut TcpConnectionV6, s: *const sock) -> Result<(), u32> {
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
    Ok(())
}

#[fexit(function = "tcp_v4_connect")]
pub fn tcp_v4_connect_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_v4_connect)
}

fn try_tcp_v4_connect(ctx: FExitContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(event) = event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    unsafe {
        let p = event as *mut NetworkMsg as *mut u8;
        // TcpConV4Established
        *p = 0;
    }

    let NetworkMsg::TcpConV4Establish(event) = event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v4_sock(event, s);
    }
    if event.saddr == 0 || event.daddr == 0 || event.sport == 0 || event.dport == 0 {
        return Err(0);
    }

    if config.expose_events {
        util::copy_proc(proc, &mut event.process);
    }
    Ok(0)
}

#[fexit(function = "tcp_v6_connect")]
pub fn tcp_v6_connect_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_v6_connect)
}

fn try_tcp_v6_connect(ctx: FExitContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(event) = event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    unsafe {
        let p = event as *mut NetworkMsg as *mut u8;
        // TcpConV6Established
        *p = 1;
    }

    let NetworkMsg::TcpConV6Establish(event) = event else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        parse_v6_sock(event, s)?;
    }
    if event.sport == 0 || event.dport == 0 {
        return Err(0);
    }

    if config.expose_events {
        util::copy_proc(proc, &mut event.process);
    }
    Ok(0)
}

#[fexit(function = "tcp_close")]
pub fn tcp_close_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_tcp_close)
}

fn try_tcp_close(ctx: FExitContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(event) = event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;
        match family {
            AF_INET => {
                let p = event as *mut NetworkMsg as *mut u8;
                // TcpConV4Closed
                *p = 2;
                let NetworkMsg::TcpConV4Close(event) = event else {
                    return Err(0);
                };
                parse_v4_sock(event, s);
                if config.expose_events {
                    util::copy_proc(proc, &mut event.process);
                }
                Ok(0)
            }
            AF_INET6 => {
                let p = event as *mut NetworkMsg as *mut u8;
                // TcpConV6Closed
                *p = 3;
                let NetworkMsg::TcpConV6Close(event) = event else {
                    return Err(0);
                };
                parse_v6_sock(event, s)?;
                if config.expose_events {
                    util::copy_proc(proc, &mut event.process);
                }
                Ok(0)
            }
            _ => Err(0),
        }
    }
}

#[fexit(function = "inet_csk_accept")]
pub fn inet_csk_accept_capture(ctx: FExitContext) -> u32 {
    event_capture!(ctx, MSG_NETWORK, false, try_inet_csk_accept)
}

fn try_inet_csk_accept(ctx: FExitContext, event: &mut Event) -> Result<u32, u32> {
    let Some(config_ptr) = NETMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::Network(event) = event else {
        return Err(0);
    };
    let pid = ctx.pid();
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    unsafe {
        let s = ctx.arg::<*const sock>(0);
        let family = (*s).__sk_common.skc_family;
        match family {
            AF_INET => {
                let p = event as *mut NetworkMsg as *mut u8;
                // TcpConV6Accepted
                *p = 4;
                let NetworkMsg::TcpConV4Accept(event) = event else {
                    return Err(0);
                };
                parse_v4_sock(event, s);

                if config.expose_events {
                    util::copy_proc(proc, &mut event.process);
                }
                Ok(0)
            }
            AF_INET6 => {
                let p = event as *mut NetworkMsg as *mut u8;
                // TcpConV6Accepted
                *p = 5;
                let NetworkMsg::TcpConV6Accept(event) = event else {
                    return Err(0);
                };
                parse_v6_sock(event, s)?;
                if config.expose_events {
                    util::copy_proc(proc, &mut event.process);
                }
                Ok(0)
            }
            _ => Err(0),
        }
    }
}
