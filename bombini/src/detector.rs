//! Detector module provides interface to manage eBPF detectors.

use aya::{Ebpf, EbpfError, EbpfLoader};

use log::debug;
use std::path::Path;

use super::loader::Loader;

// TODO: Implement Config for parameters to be set by user
const PIN_PATH: &str = "/sys/fs/bpf/bombini/";

const EVENT_MAP_NAME: &str = "EVENT_MAP";

const EVENT_MAP_SIZE: u32 = 65536;

/// Detector represents a loaded eBPF object
pub struct Detector<T> {
    /// Detector's name
    pub name: String,
    /// Aya Ebpf holds loaded eBPF objects
    aya_ebpf: Ebpf,
    /// Loader attaches to kernel hook points and initializes maps
    loader: T,
}

impl<T: Loader> Detector<T> {
    /// Construct `Detector` from object file and Loader interface implementation.
    ///
    /// # Arguments
    ///
    /// * `obj_path` - file path to ebpf object file.
    ///
    /// * `loader` - implementation of Loader interface for detector.
    pub fn create<U: AsRef<Path>>(obj_path: U, loader: T) -> Result<Self, EbpfError> {
        let aya_ebpf = EbpfLoader::new()
            .map_pin_path(PIN_PATH)
            .set_max_entries(EVENT_MAP_NAME, EVENT_MAP_SIZE)
            .load_file(obj_path.as_ref())?;
        let name = obj_path.as_ref().file_stem().unwrap().to_str().unwrap();
        Ok(Self {
            name: name.to_string(),
            aya_ebpf,
            loader,
        })
    }

    /// Load and attach all bpf programs and maps of the `Detector`.
    pub fn load(&mut self) -> Result<(), EbpfError> {
        self.loader.load(&mut self.aya_ebpf)?;
        debug!("Detector {} is loaded", self.name);
        Ok(())
    }
}
