//! Detector for Process executions and exits

use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfError};

use procfs::sys::kernel::Version;

use std::path::Path;

use super::{load_ebpf_obj, Detector};

pub struct ProcMon {
    ebpf: Ebpf,
}

impl Detector for ProcMon {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 8, 0)
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
        let exec: &mut TracePoint = self
            .ebpf
            .program_mut("execve_capture")
            .unwrap()
            .try_into()?;
        exec.load()?;
        exec.attach("sched", "sched_process_exec")?;

        let exit: &mut KProbe = self.ebpf.program_mut("exit_capture").unwrap().try_into()?;
        exit.load()?;
        exit.attach("acct_process", 0)?;
        Ok(())
    }
}
