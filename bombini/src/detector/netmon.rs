//! Network monitor detector

use aya::maps::MapError;
use aya::programs::FExit;
use aya::{Btf, Ebpf, EbpfError, EbpfLoader};

use std::{collections::HashMap, path::Path, sync::Arc};

use crate::detector::Detector;
use crate::proto::config::{NetMonConfig, Rule};
use crate::rule::serializer::{SerializedRules, netmon::TcpConnectionPredicate};

#[derive(Debug, Copy, Clone)]
enum TrafficDirection {
    Ingress,
    Egress,
}

#[derive(Debug)]
struct ConnectionControlData {
    pub direction: TrafficDirection,
    pub serialized_rules: SerializedRules<TcpConnectionPredicate>,
    pub map_sizes: HashMap<String, u32>,
}

impl ConnectionControlData {
    fn new(direction: TrafficDirection, rules: &[Rule]) -> Result<Self, anyhow::Error> {
        let mut serialized_rules = SerializedRules::new();
        serialized_rules.serialize_rules(rules)?;
        let map_sizes = serialized_rules.map_sizes(direction.map_prefix());

        Ok(ConnectionControlData {
            direction,
            serialized_rules,
            map_sizes,
        })
    }
}

impl TrafficDirection {
    fn map_prefix(&self) -> &'static str {
        match self {
            TrafficDirection::Ingress => "NETMON_INGRESS",
            TrafficDirection::Egress => "NETMON_EGRESS",
        }
    }
}

pub struct NetMon {
    ebpf: Ebpf,
    ingress: Option<Box<ConnectionControlData>>,
    egress: Option<Box<ConnectionControlData>>,
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
        if config.egress.is_none() && config.ingress.is_none() {
            anyhow::bail!("Config for egress/ingress connections must be provided");
        }
        let mut ebpf_loader = EbpfLoader::new();
        let ebpf_loader_ref = ebpf_loader.map_pin_path(maps_pin_path.as_ref());

        let ingress = if let Some(ingress_cfg) = &config.ingress {
            Some(Box::new(ConnectionControlData::new(
                TrafficDirection::Ingress,
                &ingress_cfg.rules,
            )?))
        } else {
            None
        };
        let egress = if let Some(egress_cfg) = &config.egress {
            Some(Box::new(ConnectionControlData::new(
                TrafficDirection::Egress,
                &egress_cfg.rules,
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
                    ebpf_loader_ref.set_max_entries(name, *size);
                });
        }

        if let Some(ref egress) = egress {
            egress
                .map_sizes
                .iter()
                .filter(|(_, size)| **size > 1)
                .for_each(|(name, size)| {
                    ebpf_loader_ref.set_max_entries(name, *size);
                });
        }

        let ebpf = ebpf_loader_ref.load_file(obj_path.as_ref())?;
        Ok(NetMon {
            ebpf,
            ingress,
            egress,
        })
    }
}

impl Detector for NetMon {
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(ref ingress) = self.ingress {
            ingress
                .serialized_rules
                .store_rules(&mut self.ebpf, ingress.direction.map_prefix())
                .map_err(|e| MapError::InvalidName {
                    name: e.to_string(),
                })?;
        }
        if let Some(ref egress) = self.egress {
            egress
                .serialized_rules
                .store_rules(&mut self.ebpf, egress.direction.map_prefix())
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
        let tcp_close: &mut FExit = self.ebpf.program_mut("tcp_close_v4").unwrap().try_into()?;
        tcp_close.load("tcp_close", &btf)?;
        tcp_close.attach()?;
        let tcp_close: &mut FExit = self.ebpf.program_mut("tcp_close_v6").unwrap().try_into()?;
        tcp_close.load("tcp_close", &btf)?;
        tcp_close.attach()?;
        Ok(())
    }
}
