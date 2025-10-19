//! Network monitor detector

use aya::maps::{
    hash_map::HashMap,
    lpm_trie::{Key, LpmTrie},
    Array,
};
use aya::programs::FExit;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use bombini_common::{
    config::network::{Config, IpFilterMask},
    config::procmon::ProcessFilterMask,
    constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX},
};

use crate::{
    config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME},
    init_process_filter_maps,
    proto::config::NetMonConfig,
    resize_process_filter_maps,
};

use super::Detector;

pub struct NetMon {
    ebpf: Ebpf,
    config: NetMonConfig,
}
impl Detector for NetMon {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let Some(yaml_config) = yaml_config else {
            anyhow::bail!("Config for netmon must be provided");
        };

        let config: NetMonConfig = serde_yml::from_str(yaml_config.as_ref())?;
        if config.egress.is_none() && config.ingress.is_none() {
            anyhow::bail!("Config for egress/ingress connections must be provided");
        }
        let config_opts = CONFIG.read().await;
        let mut ebpf_loader = EbpfLoader::new();
        let mut ebpf_loader_ref = ebpf_loader
            .map_pin_path(config_opts.maps_pin_path.as_ref().unwrap())
            .set_max_entries(EVENT_MAP_NAME, config_opts.event_map_size.unwrap())
            .set_max_entries(
                PROCMON_PROC_MAP_NAME,
                config_opts.procmon_proc_map_size.unwrap(),
            );
        if let Some(filter) = &config.process_filter {
            resize_process_filter_maps!(filter, ebpf_loader_ref);
        }
        resize_ip_filter_maps(&config, ebpf_loader_ref);
        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;
        Ok(NetMon { ebpf, config })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config = Config {
            filter_mask: ProcessFilterMask::empty(),
            deny_list: false,
            ip_filter_mask: IpFilterMask::empty(),
        };
        if let Some(filter) = &self.config.process_filter {
            config.filter_mask = init_process_filter_maps!(filter, &mut self.ebpf);
            config.deny_list = filter.deny_list;
        }
        init_ip_filter_maps(&mut config, &self.config, &mut self.ebpf)?;
        let mut config_map: Array<_, Config> =
            Array::try_from(self.ebpf.map_mut("NETMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, config, 0);
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        if let Some(ref egress_cfg) = self.config.egress {
            if egress_cfg.enabled {
                let tcp_v4_connect: &mut FExit = self
                    .ebpf
                    .program_mut("tcp_v4_connect_capture")
                    .unwrap()
                    .try_into()?;
                tcp_v4_connect.load("tcp_v4_connect", &btf)?;
                tcp_v4_connect.attach()?;
                let tcp_v6_connect: &mut FExit = self
                    .ebpf
                    .program_mut("tcp_v6_connect_capture")
                    .unwrap()
                    .try_into()?;
                tcp_v6_connect.load("tcp_v6_connect", &btf)?;
                tcp_v6_connect.attach()?;
            }
        }
        if let Some(ref ingress_cfg) = self.config.ingress {
            if ingress_cfg.enabled {
                let tcp_accept: &mut FExit = self
                    .ebpf
                    .program_mut("inet_csk_accept_capture")
                    .unwrap()
                    .try_into()?;
                tcp_accept.load("inet_csk_accept", &btf)?;
                tcp_accept.attach()?;
            }
        }
        let tcp_close: &mut FExit = self
            .ebpf
            .program_mut("tcp_close_capture")
            .unwrap()
            .try_into()?;
        tcp_close.load("tcp_close", &btf)?;
        tcp_close.attach()?;
        Ok(())
    }
}

#[inline]
fn resize_ip_filter_maps(config: &NetMonConfig, loader: &mut EbpfLoader) {
    if let Some(ref ingress) = config.ingress {
        if let Some(ref ipv4_filter) = ingress.ipv4_filter {
            if ipv4_filter.dst_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_DST_IP4_INGRESS_MAP_NAME,
                    ipv4_filter.dst_ip.len() as u32,
                );
            }
            if ipv4_filter.src_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_SRC_IP4_INGRESS_MAP_NAME,
                    ipv4_filter.src_ip.len() as u32,
                );
            }
        }
        if let Some(ref ipv6_filter) = ingress.ipv6_filter {
            if ipv6_filter.dst_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_DST_IP6_INGRESS_MAP_NAME,
                    ipv6_filter.dst_ip.len() as u32,
                );
            }
            if ipv6_filter.src_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_SRC_IP6_INGRESS_MAP_NAME,
                    ipv6_filter.src_ip.len() as u32,
                );
            }
        }
    }
    if let Some(ref egress) = config.egress {
        if let Some(ref ipv4_filter) = egress.ipv4_filter {
            if ipv4_filter.dst_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_DST_IP4_EGRESS_MAP_NAME,
                    ipv4_filter.dst_ip.len() as u32,
                );
            }
            if ipv4_filter.src_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_SRC_IP4_EGRESS_MAP_NAME,
                    ipv4_filter.src_ip.len() as u32,
                );
            }
        }
        if let Some(ref ipv6_filter) = egress.ipv6_filter {
            if ipv6_filter.dst_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_DST_IP6_EGRESS_MAP_NAME,
                    ipv6_filter.dst_ip.len() as u32,
                );
            }
            if ipv6_filter.src_ip.len() > 1 {
                loader.set_max_entries(
                    FILTER_SRC_IP6_EGRESS_MAP_NAME,
                    ipv6_filter.src_ip.len() as u32,
                );
            }
        }
    }
}

macro_rules! init_ipv4_filter_map {
    ($ip_list:expr, $ebpf:expr, $map_name:expr) => {{
        let mut map: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from($ebpf.map_mut($map_name).unwrap())?;
        for cidr_str in $ip_list.iter() {
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let prefix = if parts.len() == 2 {
                parts[1].parse::<u32>().unwrap_or(4)
            } else {
                32
            };
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                let key: Key<[u8; 4]> = Key::new(prefix, ip.octets());
                let _ = map.insert(&key, 0, 0);
            }
        }
    }};
}

macro_rules! init_ipv6_filter_map {
    ($ip_list:expr, $ebpf:expr, $map_name:expr) => {{
        let mut map: LpmTrie<_, [u8; 16], u8> =
            LpmTrie::try_from($ebpf.map_mut($map_name).unwrap())?;
        for cidr_str in $ip_list.iter() {
            let parts: Vec<&str> = cidr_str.splitn(2, "/").collect::<Vec<&str>>();
            let prefix = if parts.len() == 2 {
                parts[1].parse::<u32>().unwrap_or(16)
            } else {
                16 * 8
            };
            if let Ok(ip) = parts[0].parse::<Ipv6Addr>() {
                let key: Key<[u8; 16]> = Key::new(prefix, ip.octets());
                let _ = map.insert(&key, 0, 0);
            }
        }
    }};
}

#[inline]
fn init_ip_filter_maps(
    ebpf_config: &mut Config,
    config: &NetMonConfig,
    ebpf: &mut Ebpf,
) -> Result<(), EbpfError> {
    if let Some(ref ingress) = config.ingress {
        if let Some(ref ipv4_filter) = ingress.ipv4_filter {
            if !ipv4_filter.dst_ip.is_empty() {
                init_ipv4_filter_map!(ipv4_filter.dst_ip, ebpf, FILTER_DST_IP4_INGRESS_MAP_NAME);
                if ipv4_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP4_INGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP4_INGRESS_ALLOW;
                }
            }
            if !ipv4_filter.src_ip.is_empty() {
                init_ipv4_filter_map!(ipv4_filter.src_ip, ebpf, FILTER_SRC_IP4_INGRESS_MAP_NAME);
                if ipv4_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP4_INGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP4_INGRESS_ALLOW;
                }
            }
        }
        if let Some(ref ipv6_filter) = ingress.ipv6_filter {
            if !ipv6_filter.dst_ip.is_empty() {
                init_ipv6_filter_map!(ipv6_filter.dst_ip, ebpf, FILTER_DST_IP6_INGRESS_MAP_NAME);
                if ipv6_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP6_INGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP6_INGRESS_ALLOW;
                }
            }
            if !ipv6_filter.src_ip.is_empty() {
                init_ipv6_filter_map!(ipv6_filter.src_ip, ebpf, FILTER_SRC_IP6_INGRESS_MAP_NAME);
                if ipv6_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP6_INGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP6_INGRESS_ALLOW;
                }
            }
        }
    }
    if let Some(ref egress) = config.egress {
        if let Some(ref ipv4_filter) = egress.ipv4_filter {
            if !ipv4_filter.dst_ip.is_empty() {
                init_ipv4_filter_map!(ipv4_filter.dst_ip, ebpf, FILTER_DST_IP4_EGRESS_MAP_NAME);
                if ipv4_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP4_EGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP4_EGRESS_ALLOW;
                }
            }
            if !ipv4_filter.src_ip.is_empty() {
                init_ipv4_filter_map!(ipv4_filter.src_ip, ebpf, FILTER_SRC_IP4_EGRESS_MAP_NAME);
                if ipv4_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP4_EGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP4_EGRESS_ALLOW;
                }
            }
        }
        if let Some(ref ipv6_filter) = egress.ipv6_filter {
            if !ipv6_filter.dst_ip.is_empty() {
                init_ipv6_filter_map!(ipv6_filter.dst_ip, ebpf, FILTER_DST_IP6_EGRESS_MAP_NAME);
                if ipv6_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP6_EGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::DEST_IP6_EGRESS_ALLOW;
                }
            }
            if !ipv6_filter.src_ip.is_empty() {
                init_ipv6_filter_map!(ipv6_filter.src_ip, ebpf, FILTER_SRC_IP6_EGRESS_MAP_NAME);
                if ipv6_filter.deny_list {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP6_EGRESS_DENY;
                } else {
                    ebpf_config.ip_filter_mask |= IpFilterMask::SOURCE_IP6_EGRESS_ALLOW;
                }
            }
        }
    }
    Ok(())
}

// Netmon process filter map names
const FILTER_UID_MAP_NAME: &str = "NETMON_FILTER_UID_MAP";

const FILTER_EUID_MAP_NAME: &str = "NETMON_FILTER_EUID_MAP";

const FILTER_AUID_MAP_NAME: &str = "NETMON_FILTER_AUID_MAP";

const FILTER_BINPATH_MAP_NAME: &str = "NETMON_FILTER_BINPATH_MAP";

const FILTER_BINNAME_MAP_NAME: &str = "NETMON_FILTER_BINNAME_MAP";

const FILTER_BINPREFIX_MAP_NAME: &str = "NETMON_FILTER_BINPREFIX_MAP";

// Netmon ip filter map names
const FILTER_SRC_IP4_EGRESS_MAP_NAME: &str = "NETMON_FILTER_SRC_IP4_EGRESS_MAP";

const FILTER_SRC_IP4_INGRESS_MAP_NAME: &str = "NETMON_FILTER_SRC_IP4_INGRESS_MAP";

const FILTER_DST_IP4_EGRESS_MAP_NAME: &str = "NETMON_FILTER_DST_IP4_EGRESS_MAP";

const FILTER_DST_IP4_INGRESS_MAP_NAME: &str = "NETMON_FILTER_DST_IP4_INGRESS_MAP";

const FILTER_SRC_IP6_EGRESS_MAP_NAME: &str = "NETMON_FILTER_SRC_IP6_EGRESS_MAP";

const FILTER_SRC_IP6_INGRESS_MAP_NAME: &str = "NETMON_FILTER_SRC_IP6_INGRESS_MAP";

const FILTER_DST_IP6_EGRESS_MAP_NAME: &str = "NETMON_FILTER_DST_IP6_EGRESS_MAP";

const FILTER_DST_IP6_INGRESS_MAP_NAME: &str = "NETMON_FILTER_DST_IP6_INGRESS_MAP";
