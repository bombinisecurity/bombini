//! Detector provides interface to load and configure eBPF detectors

use procfs::sys::kernel::Version;

use anyhow::anyhow;
use aya::EbpfLoader;
use aya::maps::MapInfo;

use std::path::Path;

use crate::options::{EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME};

pub mod error;
pub mod filemon;
pub mod io_uringmon;
pub mod kernelmon;
pub mod netmon;
pub mod procmon;
pub mod sysenummon;

pub use error::DetectorError;

/// Maps created and sized by ProcMon and shared with other detectors via bpffs pins.
const SHARED_PINNED_MAPS: [&str; 2] = [EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME];

/// Set `max_entries` of shared pinned maps to the size of already pinned maps.
///
/// Aya refuses to reuse a pinned map whose definition doesn't match the one
/// from the eBPF object, so detectors must declare the same size that ProcMon
/// used when the map was created.
pub fn reuse_shared_pinned_maps(
    loader: &mut EbpfLoader,
    maps_pin_path: &Path,
) -> Result<(), anyhow::Error> {
    for name in SHARED_PINNED_MAPS {
        let pin = maps_pin_path.join(name);
        if pin.exists() {
            let info = MapInfo::from_pin(&pin)?;
            loader.map_max_entries(name, info.max_entries());
        }
    }
    Ok(())
}

pub trait Detector {
    /// Minimal supported kernel version for detector to load
    fn min_kenrel_verison(&self) -> Version {
        Version::new(6, 2, 0)
    }

    /// Initialize config maps for detector
    fn map_initialize(&mut self) -> Result<(), DetectorError> {
        Ok(())
    }

    /// Load and attach eBPF programs
    fn load_and_attach_programs(&mut self) -> Result<(), DetectorError>;

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
