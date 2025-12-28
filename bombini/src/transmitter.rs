//! Transmitter provides interface to send serialized event into different sources

pub mod file;
pub mod stdout;
pub mod unix_sock;

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
