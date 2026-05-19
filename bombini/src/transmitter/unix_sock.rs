//! Transmit serialized event into unix socket as client

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep};

use std::path::Path;

use crate::transmitter::Transmitter;

use log::debug;

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_COUNT: u32 = 10;

pub struct USockTransmitter {
    stream: UnixStream,
}

impl USockTransmitter {
    /// Connect to unix socket with retry
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path_ref = path.as_ref();

        for attempt in 1..=RETRY_COUNT {
            match UnixStream::connect(path_ref).await {
                Ok(stream) => {
                    debug!("Connected to {}", path_ref.display());
                    return Ok(USockTransmitter { stream });
                }
                Err(e) => {
                    debug!(
                        "Connection failed (attempt {}/{}): {}. Retrying in {:?}...",
                        attempt, RETRY_COUNT, e, RETRY_INTERVAL
                    );
                    sleep(RETRY_INTERVAL).await;
                }
            }
        }
        Err(anyhow::anyhow!(
            "Failed to connect ({}) after {} attempts",
            path_ref.display(),
            RETRY_COUNT
        ))
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
