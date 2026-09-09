//! Transmitter provides interface to send serialized event into different sources

pub mod file;
pub mod stdout;
pub mod unix_sock;

/// Events are newline delimited (JSON Lines). The delimiter is appended to the
/// payload and written together with it, so a reader only sees complete records.
pub const EVENT_DELIMITER: u8 = b'\n';

pub trait Transmitter {
    /// Transmit serialized event
    ///
    /// # Arguments
    ///
    /// * `data` - serialized event data
    fn transmit(
        &mut self,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), anyhow::Error>> + Send;
}
