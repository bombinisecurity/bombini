//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use bytes::Bytes;

use std::convert::TryFrom;
use std::path::Path;

use bombini_common::event::GenericEvent;

use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;

pub struct Monitor<'a> {
    pin_path: &'a Path,
    /// Size of raw event channel
    event_chanel_size: usize,
}

impl<'a> Monitor<'a> {
    /// Construct `Monitor`.
    ///
    /// # Arguments
    ///
    /// * `path` - pin path to event ring buffer
    ///
    /// * `channel_size` - size of raw event channel
    pub fn new<P: Into<&'a Path>>(path: P, chanel_sz: usize) -> Self {
        Monitor {
            pin_path: path.into(),
            event_chanel_size: chanel_sz,
        }
    }

    /// Start monitoring the events.
    ///
    /// # Arguments
    ///
    /// `transmitter` - interface for sending events
    ///
    /// `transmuters` - registry for transmuting ebpf events
    pub async fn monitor<T: Transmitter + Send + 'static>(
        &self,
        mut transmitter: T,
        transmuters: TransmuterRegistry,
    ) {
        let (tx, mut rx) = mpsc::channel::<Bytes>(self.event_chanel_size);
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(self.pin_path).unwrap(),
        ))
        .unwrap();

        tokio::spawn(async move {
            let mut poll = AsyncFd::new(ring_buf).unwrap();
            loop {
                let mut guard = poll.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    tx.send(Bytes::from(item.to_vec())).await.unwrap();
                }
                guard.clear_ready();
            }
        });
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let event: &GenericEvent = unsafe { &*message.as_ptr().cast::<GenericEvent>() };
                if let Ok(data) = transmuters.transmute(event).await {
                    let _ = transmitter.transmit(data).await;
                }
            }
        });
    }
}
