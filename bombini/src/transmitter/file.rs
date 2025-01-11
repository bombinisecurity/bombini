//! Transmit serialized event into file

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;

use std::path::Path;

use crate::transmitter::Transmitter;

pub struct FileTransmitter {
    file: File,
}

impl FileTransmitter {
    /// Construct transmitter for sending events to file.
    /// File options: create + append
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .await?;
        Ok(FileTransmitter { file })
    }
}

impl Drop for FileTransmitter {
    fn drop(&mut self) {
        futures_executor::block_on(async {
            self.file.shutdown().await.unwrap();
        });
    }
}

impl Transmitter for FileTransmitter {
    async fn transmit(&mut self, mut data: Vec<u8>) -> Result<(), anyhow::Error> {
        // delimiter
        data.push(b'\n');
        self.file.write_all(&data).await?;
        Ok(())
    }
}
