//! Detector provides interface to load and configure eBPF detectors

use aya::{Ebpf, EbpfError, EbpfLoader};

use procfs::sys::kernel::Version;

use std::path::Path;

use anyhow::anyhow;

use crate::config::{CONFIG, EVENT_MAP_NAME};

pub mod gtfobins;
pub mod procmon;

pub trait Detector {
    /// Construct `Detector` from object file.
    ///
    /// # Arguments
    ///
    /// * `obj_path` - file path to ebpf object file
    ///
    /// * `config_path` - file path to yaml initialization config.
    async fn new<U: AsRef<Path>>(
        obj_path: U,
        config_path: Option<U>,
    ) -> Result<Self, anyhow::Error>
    where
        Self: Sized;

    /// Minimal supported kernel version for detector to load
    fn min_kenrel_verison(&self) -> Version;

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
pub async fn load_ebpf_obj<U: AsRef<Path>>(obj_path: U) -> Result<Ebpf, EbpfError> {
    let config = CONFIG.read().await;
    EbpfLoader::new()
        .map_pin_path(config.maps_pin_path.as_ref().unwrap())
        .set_max_entries(EVENT_MAP_NAME, config.event_map_size.unwrap())
        .load_file(obj_path.as_ref())
}
