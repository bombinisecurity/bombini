//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use bytes::Bytes;
use log::info;

use std::convert::TryFrom;
use std::path::Path;

use bombini_common::event::Event;

use crate::transmuter::Transmuter;

pub struct Monitor<'a> {
    pub pin_path: &'a Path,
    /// Size of raw event channel
    pub event_chanel_size: usize,
}

impl<'a> Monitor<'a> {
    /// Construct `Monitor`.
    ///
    /// # Arguments
    ///
    /// * `channel_size` - size of raw event channel.
    pub fn new<P: Into<&'a Path>>(path: P, chanel_sz: usize) -> Self {
        Monitor {
            pin_path: path.into(),
            event_chanel_size: chanel_sz,
        }
    }

    /// Start monitoring the events.
    pub async fn monitor(&self) {
        let (tx, mut rx) = mpsc::channel::<Bytes>(self.event_chanel_size);
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(self.pin_path).unwrap(),
        ))
        .unwrap();
        let transmuter = Transmuter;

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
                let s: Event = unsafe { std::ptr::read(message.as_ptr() as *const _) };
                info!("{}", transmuter.transmute(s).await.unwrap());
            }
        });
    }
}
