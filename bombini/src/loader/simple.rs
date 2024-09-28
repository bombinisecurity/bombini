//! Loader for simple detector

use aya::programs::KProbe;
use aya::{Ebpf, EbpfError};

use procfs::sys::kernel::Version;

use super::Loader;

pub struct SimpleLoader;

impl Loader for SimpleLoader {
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 7, 0)
    }

    fn load(&self, loader: &mut Ebpf) -> Result<(), EbpfError> {
        let program: &mut KProbe = loader.program_mut("simple").unwrap().try_into()?;
        program.load()?;
        program.attach("security_bprm_check", 0)?;
        Ok(())
    }
}
