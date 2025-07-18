//! Transmit serialized event into stdout

use tokio::io::{self, AsyncWriteExt};

use super::Transmitter;

pub struct StdoutTransmitter;

impl Transmitter for StdoutTransmitter {
    async fn transmit(&mut self, mut data: Vec<u8>) -> Result<(), anyhow::Error> {
        data.push(b'\n');
        let mut stdout = io::stdout();
        stdout.write_all(&data).await?;
        Ok(())
    }
}
