//! GTFOBins config

pub const MAX_FILENAME_SIZE: usize = 15;

pub const MAX_ARGS_SIZE: usize = 64;

pub type GTFOBinsKey = [u8; MAX_FILENAME_SIZE + 1 + MAX_ARGS_SIZE];
