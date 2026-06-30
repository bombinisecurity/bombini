//! Network monitor detector

use aya::maps::{Array, MapError};
use aya::programs::{FExit, Lsm};
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};
use bombini_common::config::netmon::NetMonKernelConfig;
use bombini_common::constants::MAX_FILE_PATH;
use bombini_common::event::network::NetworkEventNumber;

use std::{collections::HashMap, path::Path, sync::Arc};

use crate::detector::Detector;
use crate::proto::config::{NetMonConfig, Rule};
use crate::rule::serializer::PredicateSerializer;
use crate::rule::serializer::netmon::{SocketConnectPredicate, SocketCreatePredicate};
use crate::rule::serializer::{SerializedRules, netmon::TcpConnectionPredicate};

#[derive(Debug, Copy, Clone)]
enum NetMonHook {
    Ingress,
    Egress,
    SocketCreate,
    SocketConnect,
}

struct ConnectionControlData<T: PredicateSerializer + Default> {
    pub hook: NetMonHook,
    pub serialized_rules: SerializedRules<T>,
    pub map_sizes: HashMap<String, u32>,
}

impl<T: PredicateSerializer + Default> ConnectionControlData<T> {
    fn new(hook: NetMonHook, rules: &[Rule]) -> Result<Self, anyhow::Error> {
        let mut serialized_rules = SerializedRules::new();
        serialized_rules.serialize_rules(rules)?;
        let map_sizes = serialized_rules.map_sizes(hook.map_prefix());

        Ok(ConnectionControlData {
            hook,
            serialized_rules,
            map_sizes,
        })
    }
}

impl NetMonHook {
    fn map_prefix(&self) -> &'static str {
        match self {
            NetMonHook::Ingress => "NETMON_INGRESS",
            NetMonHook::Egress => "NETMON_EGRESS",
            NetMonHook::SocketCreate => "NETMON_SOCKET_CREATE",
            NetMonHook::SocketConnect => "NETMON_SOCKET_CONNECT",
        }
    }
}

pub struct NetMon {
    ebpf: Ebpf,
    config: NetMonKernelConfig,
    ingress: Option<Box<ConnectionControlData<TcpConnectionPredicate>>>,
    egress: Option<Box<ConnectionControlData<TcpConnectionPredicate>>>,
    socket_create: Option<Box<ConnectionControlData<SocketCreatePredicate>>>,
    socket_connect: Option<Box<ConnectionControlData<SocketConnectPredicate>>>,
}

impl NetMon {
    pub fn new<P>(
        obj_path: P,
        maps_pin_path: P,
        config: Arc<NetMonConfig>,
    ) -> Result<Self, anyhow::Error>
    where
        P: AsRef<Path>,
    {
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.default_map_pin_directory(maps_pin_path.as_ref());
        let mut detector_config = NetMonKernelConfig {
            sandbox_mode: [None; NetworkEventNumber::TotalNetworkEvents as usize],
        };

        let ingress = if let Some(ingress_cfg) = &config.ingress
            && ingress_cfg.enabled
        {
            Some(Box::new(ConnectionControlData::new(
                NetMonHook::Ingress,
                &ingress_cfg.rules,
            )?))
        } else {
            None
        };
        let egress = if let Some(egress_cfg) = &config.egress
            && egress_cfg.enabled
        {
            Some(Box::new(ConnectionControlData::new(
                NetMonHook::Egress,
                &egress_cfg.rules,
            )?))
        } else {
            None
        };
        let socket_create = if let Some(socket_create_cfg) = &config.socket_create
            && socket_create_cfg.enabled
        {
            if let Some(sandbox) = &socket_create_cfg.sandbox
                && sandbox.enabled
            {
                detector_config.sandbox_mode[NetworkEventNumber::SocketCreate as usize] =
                    Some(sandbox.deny_list);
            }
            Some(Box::new(ConnectionControlData::new(
                NetMonHook::SocketCreate,
                &socket_create_cfg.rules,
            )?))
        } else {
            None
        };
        let socket_connect = if let Some(socket_connect_cfg) = &config.socket_connect
            && socket_connect_cfg.enabled
        {
            if let Some(sandbox) = &socket_connect_cfg.sandbox
                && sandbox.enabled
            {
                detector_config.sandbox_mode[NetworkEventNumber::SocketConnect as usize] =
                    Some(sandbox.deny_list);
            }
            Some(Box::new(ConnectionControlData::new(
                NetMonHook::SocketConnect,
                &socket_connect_cfg.rules,
            )?))
        } else {
            None
        };

        // Resize maps
        if let Some(ref ingress) = ingress {
            ingress
                .map_sizes
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    ebpf_loader_ref.map_max_entries(name, *size);
                });
        }

        if let Some(ref egress) = egress {
            egress
                .map_sizes
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    ebpf_loader_ref.map_max_entries(name, *size);
                });
        }

        if let Some(ref socket_create) = socket_create {
            socket_create
                .map_sizes
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    ebpf_loader_ref.map_max_entries(name, *size);
                });
        }

        if let Some(ref socket_connect) = socket_connect {
            socket_connect
                .map_sizes
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    ebpf_loader_ref.map_max_entries(name, *size);
                });
        }

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;
        Ok(NetMon {
            ebpf,
            config: detector_config,
            ingress,
            egress,
            socket_create,
            socket_connect,
        })
    }
}

impl Detector for NetMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        let mut config_map: Array<_, NetMonKernelConfig> =
            Array::try_from(self.ebpf.map_mut("NETMON_CONFIG").unwrap())?;
        let _ = config_map.set(0, self.config, 0);
        let mut zero_map: Array<_, [u8; MAX_FILE_PATH]> =
            Array::try_from(self.ebpf.map_mut("ZERO_PATH_MAP").unwrap())?;
        zero_map.set(0, [0; MAX_FILE_PATH], 0)?;

        if let Some(ref ingress) = self.ingress {
            ingress
                .serialized_rules
                .store_rules(&mut self.ebpf, ingress.hook.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        } else {
            // We need to create an empty map for the ingress rules
            SerializedRules::<TcpConnectionPredicate>::new()
                .store_rules(&mut self.ebpf, NetMonHook::Ingress.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        }
        if let Some(ref egress) = self.egress {
            egress
                .serialized_rules
                .store_rules(&mut self.ebpf, egress.hook.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        } else {
            // We need to create an empty map for the egress rules
            SerializedRules::<TcpConnectionPredicate>::new()
                .store_rules(&mut self.ebpf, NetMonHook::Egress.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        }

        if let Some(ref socket_create) = self.socket_create {
            socket_create
                .serialized_rules
                .store_rules(&mut self.ebpf, socket_create.hook.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        }
        if let Some(ref socket_connect) = self.socket_connect {
            socket_connect
                .serialized_rules
                .store_rules(&mut self.ebpf, socket_connect.hook.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        }

        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        if self.egress.is_some() {
            let tcp_v4_connect: &mut FExit = self
                .ebpf
                .program_mut("tcp_v4_connect")
                .unwrap()
                .try_into()?;
            tcp_v4_connect.load("tcp_v4_connect", &btf)?;
            tcp_v4_connect.attach()?;
            let tcp_v6_connect: &mut FExit = self
                .ebpf
                .program_mut("tcp_v6_connect")
                .unwrap()
                .try_into()?;
            tcp_v6_connect.load("tcp_v6_connect", &btf)?;
            tcp_v6_connect.attach()?;
        }
        if self.ingress.is_some() {
            let tcp_accept: &mut FExit = self
                .ebpf
                .program_mut("inet_csk_accept")
                .unwrap()
                .try_into()?;
            tcp_accept.load("inet_csk_accept", &btf)?;
            tcp_accept.attach()?;
        }
        if self.egress.is_some() || self.ingress.is_some() {
            let tcp_close: &mut FExit = self.ebpf.program_mut("tcp_close").unwrap().try_into()?;
            tcp_close.load("tcp_close", &btf)?;
            tcp_close.attach()?;
        }

        if self.socket_create.is_some() {
            let socket_create: &mut Lsm = self
                .ebpf
                .program_mut("socket_create_capture")
                .unwrap()
                .try_into()?;
            socket_create.load("socket_create", &btf)?;
            socket_create.attach()?;
        }
        if self.socket_connect.is_some() {
            let socket_connect: &mut Lsm = self
                .ebpf
                .program_mut("socket_connect_capture")
                .unwrap()
                .try_into()?;
            socket_connect.load("socket_connect", &btf)?;
            socket_connect.attach()?;
        }

        Ok(())
    }
}
