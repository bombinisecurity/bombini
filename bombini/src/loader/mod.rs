//! Loader provide interface to load eBPF detectors

use aya::{Ebpf, EbpfError};

use procfs::sys::kernel::Version;

pub mod gtfobins;
pub mod simple;

pub trait Loader {
    /// Minimal supported kernel version for detector to load
    fn min_kenrel_verison(&self) -> Version;

    /// Attach eBPF programs and initialize maps
    fn load(&self, loader: &mut Ebpf) -> Result<(), EbpfError>;
}
