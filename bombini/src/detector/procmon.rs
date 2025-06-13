//! Detector for Process executions and exits

use aya::maps::Array;
use aya::programs::{BtfTracePoint, FEntry, Lsm};
use aya::{Btf, Ebpf, EbpfError};

use yaml_rust2::YamlLoader;

use std::path::Path;

use bombini_common::config::procmon::{Config, ProcessFilterMask};

use super::{load_ebpf_obj, Detector};

pub struct ProcMon {
    ebpf: Ebpf,
    config: Option<Config>,
}

impl Detector for ProcMon {
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        U: AsRef<str>,
        P: AsRef<Path>,
    {
        let ebpf = load_ebpf_obj(obj_path).await?;

        if let Some(yaml_config) = yaml_config {
            let mut config = Config {
                expose_events: false,
                filter_mask: ProcessFilterMask::empty(),
                deny_list: false,
            };

            let docs = YamlLoader::load_from_str(yaml_config.as_ref())?;
            let doc = &docs[0];

            config.expose_events = doc["expose-events"].as_bool().unwrap_or(false);

            Ok(ProcMon {
                ebpf,
                config: Some(config),
            })
        } else {
            Ok(ProcMon { ebpf, config: None })
        }
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        if let Some(config) = self.config {
            let mut config_map: Array<_, Config> =
                Array::try_from(self.ebpf.map_mut("PROCMON_CONFIG").unwrap())?;
            let _ = config_map.set(0, config, 0);
        }
        Ok(())
    }

    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError> {
        let btf = Btf::from_sys_fs()?;
        let exec: &mut BtfTracePoint = self
            .ebpf
            .program_mut("execve_capture")
            .unwrap()
            .try_into()?;
        exec.load("sched_process_exec", &btf)?;
        exec.attach()?;

        let fork: &mut FEntry = self.ebpf.program_mut("fork_capture").unwrap().try_into()?;
        fork.load("wake_up_new_task", &btf)?;
        fork.attach()?;

        let exit: &mut FEntry = self.ebpf.program_mut("exit_capture").unwrap().try_into()?;
        exit.load("acct_process", &btf)?;
        exit.attach()?;

        let program: &mut Lsm = self.ebpf.program_mut("creds_capture").unwrap().try_into()?;
        program.load("bprm_committing_creds", &btf)?;
        program.attach()?;
        Ok(())
    }
}
