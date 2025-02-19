//! Detector for Process executions and exits

use aya::programs::{BtfTracePoint, FEntry, Lsm};
use aya::{Btf, Ebpf, EbpfError};

use procfs::sys::kernel::Version;

use std::path::Path;

use super::{load_ebpf_obj, Detector};

pub struct ProcMon {
    ebpf: Ebpf,
}

impl Detector for ProcMon {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 10, 0)
    }

    async fn new<U: AsRef<Path>>(
        obj_path: U,
        _config_path: Option<U>,
    ) -> Result<Self, anyhow::Error> {
        let ebpf = load_ebpf_obj(obj_path).await?;
        Ok(ProcMon { ebpf })
    }

    fn map_initialize(&mut self) -> Result<(), EbpfError> {
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
