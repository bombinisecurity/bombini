//! Transmit serialized event into log

use log::info;

use super::Transmitter;

/// logger log::* must be initialized before
pub struct LogTransmitter;

impl Transmitter for LogTransmitter {
    async fn transmit(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        Ok(info!("{}", String::from_utf8(data)?))
    }
}
