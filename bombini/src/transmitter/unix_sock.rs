//! Transmit serialized event into unix socket as client

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use std::path::Path;

use crate::transmitter::Transmitter;

use log::info;

pub struct USockTransmitter {
    stream: UnixStream,
}

impl USockTransmitter {
    /// Connect to unix socket
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let transmitter = USockTransmitter {
            stream: UnixStream::connect(path.as_ref()).await?,
        };
        log::debug!("Connected to {}", path.as_ref().display());
        Ok(transmitter)
    }
}

impl Drop for USockTransmitter {
    fn drop(&mut self) {
        futures_executor::block_on(async {
            self.stream.shutdown().await.unwrap();
        });
    }
}

impl Transmitter for USockTransmitter {
    async fn transmit(&mut self, mut data: Vec<u8>) -> Result<(), anyhow::Error> {
        // Delimiter
        data.push(b'\n');
        loop {
            self.stream.writable().await?;
            match self.stream.try_write(&data) {
                Ok(_) => {
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}
