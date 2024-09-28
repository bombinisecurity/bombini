//! Loader for gtfobins detector

use aya::programs::TracePoint;
use aya::{Ebpf, EbpfError};

use procfs::sys::kernel::Version;

use super::Loader;

pub struct GtfobinsLoader;

impl Loader for GtfobinsLoader {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 7, 0)
    }

    fn load(&self, loader: &mut Ebpf) -> Result<(), EbpfError> {
        let program: &mut TracePoint = loader.program_mut("gtfobins_detect").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;
        Ok(())
    }
}
