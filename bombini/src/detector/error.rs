//! Unified error type for Detector trait methods

use aya::{BtfError, EbpfError, maps::MapError, programs::ProgramError};

#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    #[error(transparent)]
    Ebpf(#[from] EbpfError),
    #[error(transparent)]
    Map(#[from] MapError),
    #[error(transparent)]
    Btf(#[from] BtfError),
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
