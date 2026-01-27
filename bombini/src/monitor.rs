//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{Duration, Instant},
};

use bytes::Bytes;

use std::convert::TryFrom;

use bombini_common::event::GenericEvent;

use crate::config::Config;
use crate::k8s_info::K8sInfo;
use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;

pub struct Monitor;

impl Monitor {
    /// Start monitoring the events.
    ///
    /// # Arguments
    ///
    /// * `config` - Bombini Config
    ///
    /// * `transmitter` - interface for sending events
    pub async fn monitor<T: Transmitter + Send + 'static>(
        &self,
        config: &Config,
        mut transmitter: T,
        k8s_info: K8sInfo,
    ) {
        let (tx, mut rx) = mpsc::channel::<Bytes>(config.options.event_channel_size.unwrap());
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(config.options.event_pin_path()).unwrap(),
        ))
        .unwrap();
        let mut last_gc = Instant::now();
        let gc_period: Duration = Duration::from_secs(config.options.gc_period.unwrap());
        let mut transmuters = TransmuterRegistry::new(config, k8s_info);

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
                let transmuted = transmuters.transmute(event);
                if let Ok(data) = transmuted {
                    let _ = transmitter.transmit(data).await;
                } else {
                    println!("{}", transmuted.err().unwrap());
                }

                if last_gc.elapsed() >= gc_period {
                    transmuters.retain_caches();
                    last_gc = Instant::now();
                }
            }
        });
    }
}
