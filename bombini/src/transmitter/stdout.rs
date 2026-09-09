//! Transmit serialized event into stdout

use tokio::io::{self, AsyncWriteExt, Stdout};

use super::{EVENT_DELIMITER, Transmitter};

pub struct StdoutTransmitter {
    /// Kept for the whole agent lifetime: `Stdout` holds the state of an in flight
    /// write, so a per event handle allocates on the hot path.
    stdout: Stdout,
}

impl StdoutTransmitter {
    pub fn new() -> Self {
        Self {
            stdout: io::stdout(),
        }
    }
}

impl Default for StdoutTransmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Transmitter for StdoutTransmitter {
    async fn transmit(&mut self, mut data: Vec<u8>) -> Result<(), anyhow::Error> {
        data.push(EVENT_DELIMITER);
        self.stdout.write_all(&data).await?;
        Ok(())
    }
}
