//! Transmit serialized event into file

use anyhow::Ok;
use file_rotate::compression::Compression;
use file_rotate::suffix::AppendCount;
use file_rotate::{ContentLimit, FileRotate};
use std::fs::OpenOptions;
use std::io::Write;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::options::FileLogOptions;
use crate::transmitter::Transmitter;

const MEGABYTE: usize = 1024 * 1024;

pub struct FileTransmitter {
    /// Channel for sending events to log thread.
    tx: Sender<Vec<u8>>,
}

impl FileTransmitter {
    /// Construct transmitter for sending events to file.
    /// File options: create + append
    pub async fn new(
        mut log_options: FileLogOptions,
        channel_size: usize,
    ) -> Result<Self, anyhow::Error> {
        if log_options.log_file.is_none() {
            anyhow::bail!("Log file path is not set");
        }

        let (tx, mut rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
            tokio::sync::mpsc::channel(channel_size);

        std::thread::spawn(move || {
            let mut file_options = OpenOptions::new();
            file_options.create(true).append(true);
            let compression = if log_options.log_file_compression {
                Compression::OnRotate(0)
            } else {
                Compression::None
            };
            let mut log = FileRotate::new(
                log_options.log_file.take().unwrap(),
                AppendCount::new(log_options.log_file_rotations),
                ContentLimit::BytesSurpassed(log_options.log_file_size * MEGABYTE),
                compression,
                Some(file_options),
            );
            while let Some(data) = rx.blocking_recv() {
                // delimiter
                log.write_all(b"\n").unwrap();
                log.write_all(&data).unwrap();
            }
        });
        Ok(FileTransmitter { tx })
    }
}

impl Transmitter for FileTransmitter {
    async fn transmit(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.tx.send(data).await?;
        Ok(())
    }
}
