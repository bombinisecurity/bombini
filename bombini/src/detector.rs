//! Detector provides interface to load and configure eBPF detectors

use aya::EbpfError;

use procfs::sys::kernel::Version;

use anyhow::anyhow;

pub mod filemon;
pub mod filemon_new;
pub mod gtfobins;
pub mod io_uringmon;
pub mod netmon;
pub mod procmon;

pub trait Detector {
    /// Minimal supported kernel version for detector to load
    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 2, 0)
    }

    /// Initialize config maps for detector
    fn map_initialize(&mut self) -> Result<(), EbpfError> {
        Ok(())
    }

    /// Load and attach eBPF programs
    fn load_and_attach_programs(&mut self) -> Result<(), EbpfError>;

    /// Load Detector: load and attach all bpf programs and initialize all maps.
    fn load(&mut self) -> Result<(), anyhow::Error> {
        let kernel_ver = Version::current()?;
        let min_ver = self.min_kenrel_verison();
        if kernel_ver < min_ver {
            return Err(anyhow!(
                "To load detector kernel version ({:?}) must be >= {:?}",
                kernel_ver,
                min_ver
            ));
        }
        self.map_initialize()?;
        self.load_and_attach_programs()?;
        Ok(())
    }
}
