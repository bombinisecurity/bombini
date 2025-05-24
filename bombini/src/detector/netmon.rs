//! Network monitor detector

use aya::maps::Array;
use aya::programs::FExit;
use aya::{Btf, Ebpf, EbpfError};

use procfs::sys::kernel::Version;
use yaml_rust2::YamlLoader;

use std::path::Path;

use bombini_common::config::network::Config;

use super::{load_ebpf_obj, Detector};

pub struct NetMon {
    ebpf: Ebpf,
    config: Option<Config>,
}
impl Detector for NetMon {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 11, 0)
    }

    async fn new<U: AsRef<Path>>(
        obj_path: U,
        config_path: Option<U>,
    ) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        if let Some(config_path) = config_path {
            let mut config = Config {
                expose_events: false,
            };

            let s = std::fs::read_to_string(config_path.as_ref())?;
            let docs = YamlLoader::load_from_str(&s)?;
            let doc = &docs[0];

            config.expose_events = doc["expose-events"].as_bool().unwrap_or(false);

            Ok(NetMon {
                ebpf,
                config: Some(config),
            })
        } else {
            Ok(NetMon { ebpf, config: None })
        }
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(config) = self.config {
            let mut config_map: Array<_, Config> =
                Array::try_from(self.ebpf.map_mut("NETMON_CONFIG").unwrap())?;
            let _ = config_map.set(0, config, 0);
        }
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
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
        Ok(())
    }
}
