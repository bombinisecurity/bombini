//! Detector module provides interface to manage eBPF detectors.

use aya::EbpfError;

use log::debug;

use super::loader::Loader;

/// Detector represents a loaded eBPF object
pub struct Detector<T> {
    /// Detector's name
    pub name: String,
    /// Loader attaches to kernel hook points and initializes maps
    loader: T,
}

impl<T: Loader> Detector<T> {
    /// Construct `Detector` from object file and Loader interface implementation.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the detector.
    ///
    /// * `loader` - implementation of Loader interface for detector.
    pub fn create(name: &str, loader: T) -> Result<Self, EbpfError> {
        Ok(Self {
            name: name.to_string(),
            loader,
        })
    }

    /// Load Detector: load and attach all bpf programs and initialize all maps.
    pub fn load(&mut self) -> Result<(), EbpfError> {
        self.loader.map_initialize()?;
        self.loader.load_and_attach()?;
        debug!("Detector {} is loaded", self.name);
        Ok(())
    }
}
