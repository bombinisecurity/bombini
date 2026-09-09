//! Transmit serialized event into file

use anyhow::Ok;
use file_rotate::compression::Compression;
use file_rotate::suffix::AppendCount;
use file_rotate::{ContentLimit, FileRotate};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::metrics::BombiniCounter;
use crate::options::FileLogOptions;
use crate::transmitter::{EVENT_DELIMITER, Transmitter};

const MEGABYTE: usize = 1024 * 1024;

pub struct FileTransmitter {
    /// Channel for sending events to log thread.
    tx: Sender<Vec<u8>>,
}

impl FileTransmitter {
    /// Construct transmitter for sending events to file.
    /// File options: create + append
    ///
    /// # Arguments
    ///
    /// * `log_options` - event log file options
    ///
    /// * `channel_size` - number of events buffered before the log thread
    ///
    /// * `events_lost` - incremented for every event the log thread failed to write.
    ///   Write errors happen outside `transmit`, its return value can't report them.
    pub async fn new(
        mut log_options: FileLogOptions,
        channel_size: usize,
        events_lost: Arc<BombiniCounter>,
    ) -> Result<Self, anyhow::Error> {
        let Some(log_file) = log_options.log_file.take() else {
            anyhow::bail!("Log file path is not set");
        };

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
                log_file,
                AppendCount::new(log_options.rotations()),
                ContentLimit::BytesSurpassed(log_options.size_mb() * MEGABYTE),
                compression,
                Some(file_options),
            );
            while let Some(mut data) = rx.blocking_recv() {
                data.push(EVENT_DELIMITER);
                // Logged at debug: a broken sink (e.g. ENOSPC) fails for every event,
                // the loss is visible in the metric
                if let Err(e) = log.write_all(&data) {
                    events_lost.inc();
                    log::debug!("Failed to write event to log file: {e}");
                }
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
