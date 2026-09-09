//! Transmit serialized event into unix socket as client

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::{Duration, Instant, sleep};

use std::path::{Path, PathBuf};

use crate::transmitter::{EVENT_DELIMITER, Transmitter};

use log::{debug, warn};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_COUNT: u32 = 10;

pub struct USockTransmitter {
    /// Socket path, kept to be able to reconnect
    path: PathBuf,
    /// None while disconnected
    stream: Option<UnixStream>,
    /// While the peer is down, connect() is not called more often than RETRY_INTERVAL
    reconnect_after: Instant,
}

impl USockTransmitter {
    /// Connect to unix socket with retry
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path = path.as_ref().to_path_buf();
        let stream = Self::connect_with_retry(&path).await?;
        Ok(USockTransmitter {
            path,
            stream: Some(stream),
            reconnect_after: Instant::now(),
        })
    }

    /// Connect at start up, waiting for the collector to come up
    async fn connect_with_retry(path: &Path) -> Result<UnixStream, anyhow::Error> {
        for attempt in 1..=RETRY_COUNT {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    debug!("Connected to {}", path.display());
                    return Ok(stream);
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
            path.display(),
            RETRY_COUNT
        ))
    }

    /// Reconnect to a peer that went away: a single connect() attempt, at most one per
    /// RETRY_INTERVAL. The event pipeline is one task, waiting here for the collector
    /// to come back would push the loss into the ring buffer.
    async fn reconnect(&mut self) -> Result<(), anyhow::Error> {
        if Instant::now() < self.reconnect_after {
            anyhow::bail!("{} is not connected", self.path.display());
        }
        match UnixStream::connect(&self.path).await {
            Ok(stream) => {
                debug!("Reconnected to {}", self.path.display());
                self.stream = Some(stream);
                Ok(())
            }
            Err(e) => {
                self.reconnect_after = Instant::now() + RETRY_INTERVAL;
                Err(anyhow::anyhow!(
                    "Failed to reconnect to {}: {e}",
                    self.path.display()
                ))
            }
        }
    }
}

impl Drop for USockTransmitter {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        let path = self.path.clone();
        futures_executor::block_on(async move {
            if let Err(e) = stream.shutdown().await {
                debug!("Failed to shutdown {}: {e}", path.display());
            }
        });
    }
}

impl Transmitter for USockTransmitter {
    async fn transmit(&mut self, mut data: Vec<u8>) -> Result<(), anyhow::Error> {
        // Appended once, before the attempts: a retry must not add a second delimiter
        data.push(EVENT_DELIMITER);

        // Two attempts: a peer restarted since the previous event is only detected by
        // the failing write, and the event should survive that.
        let mut last_err = None;
        for attempt in 0..2 {
            if self.stream.is_none()
                && let Err(e) = self.reconnect().await
            {
                last_err = Some(e);
                break;
            }
            let Some(stream) = self.stream.as_mut() else {
                break;
            };
            // write_all handles partial writes, try_write silently truncated the record
            match stream.write_all(&data).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.stream = None;
                    if attempt == 0 {
                        warn!(
                            "Failed to write to {}: {e}. Reconnecting...",
                            self.path.display()
                        );
                        // The event still gets its second chance right away
                        self.reconnect_after = Instant::now();
                    }
                    last_err = Some(e.into());
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("{} is not connected", self.path.display())))
    }
}
