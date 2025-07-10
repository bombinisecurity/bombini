//! Detector provides interface to load and configure eBPF detectors

use aya::{Ebpf, EbpfError, EbpfLoader};

use procfs::sys::kernel::Version;

use std::path::Path;

use anyhow::anyhow;

use crate::config::{CONFIG, EVENT_MAP_NAME, PROCMON_PROC_MAP_NAME};

pub mod filemon;
pub mod gtfobins;
pub mod histfile;
pub mod io_uringmon;
pub mod netmon;
pub mod procmon;

pub trait Detector {
    /// Construct `Detector` from object file.
    ///
    /// # Arguments
    ///
    /// * `obj_path` - file path to ebpf object file
    ///
    /// * `config` - yaml initialization config.
    async fn new<P, U>(obj_path: P, yaml_config: Option<U>) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
        U: AsRef<str>,
        P: AsRef<Path>;

    /// Minimal supported kernel version for detector to load
    fn min_kenrel_verison(&self) -> Version {
        Version::new(5, 15, 0)
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

/// Load epbf object file.
///
/// # Arguments
///
/// * `obj_path` - file path to ebpf object file.
#[inline(always)]
pub async fn load_ebpf_obj<P: AsRef<Path>>(obj_path: P) -> Result<Ebpf, EbpfError> {
    let config = CONFIG.read().await;
    EbpfLoader::new()
        .map_pin_path(config.maps_pin_path.as_ref().unwrap())
        .set_max_entries(EVENT_MAP_NAME, config.event_map_size.unwrap())
        .set_max_entries(PROCMON_PROC_MAP_NAME, config.procmon_proc_map_size.unwrap())
        .load_file(obj_path.as_ref())
}
