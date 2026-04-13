//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{Duration, Instant},
};

use std::{convert::TryFrom, path::PathBuf, sync::Arc};

use bombini_common::event::GenericEvent;

use crate::metrics::BombiniCounter;
use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;
use crate::{config::Config, metrics};

mod bpf_errors;

pub struct Monitor {
    events_exported_total: Arc<BombiniCounter>,
    userspace_events_lost: Arc<BombiniCounter>,
    bpf_errors_monitor: bpf_errors::BpfErrorsMonitor,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            events_exported_total: Arc::new(BombiniCounter::new(
                "bombini_user_events_exported",
                "Number of events exported",
            )),
            userspace_events_lost: Arc::new(BombiniCounter::new(
                "bombini_user_events_lost",
                "Number of events lost in user space",
            )),
            bpf_errors_monitor: bpf_errors::BpfErrorsMonitor::new(),
        }
    }
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
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(config.options.event_channel_size.unwrap());
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(config.options.event_pin_path()).unwrap(),
        ))
        .unwrap();
        let mut last_gc = Instant::now();
        let gc_period: Duration = Duration::from_secs(config.options.gc_period.unwrap());
        let mut transmuters = TransmuterRegistry::new(config);

        // Start bpf errors monitor
        let maps_pin_path = PathBuf::from(config.options.maps_pin_path.as_ref().unwrap());
        self.bpf_errors_monitor
            .monitor_errors(maps_pin_path)
            .await
            .unwrap();

        tokio::spawn(async move {
            let mut poll = AsyncFd::new(ring_buf).unwrap();
            loop {
                let mut guard = poll.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    tx.send(item.to_vec()).await.unwrap();
                }
                guard.clear_ready();
            }
        });
        let events_exported_metric = self.events_exported_total.clone();
        let userspace_events_lost = self.userspace_events_lost.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let event: &GenericEvent = unsafe { &*message.as_ptr().cast::<GenericEvent>() };
                let transmuted = transmuters.transmute(event);
                if let Ok(data) = transmuted {
                    if let Err(e) = transmitter.transmit(data).await {
                        log::warn!("Failed to transmit event: {}", e);
                        userspace_events_lost.inc();
                    } else {
                        events_exported_metric.inc();
                    }
                } else {
                    log::debug!("{}", transmuted.err().unwrap());
                    userspace_events_lost.inc();
                }

                if last_gc.elapsed() >= gc_period {
                    transmuters.retain_caches();
                    last_gc = Instant::now();
                }
            }
        });
    }
}

impl metrics::MetricRegister for Monitor {
    fn register_metrics(&self, registry: &mut metrics::BombiniMetricServer) {
        registry.register(&*self.events_exported_total);
        registry.register(&*self.userspace_events_lost);
        registry.register_metrics(&self.bpf_errors_monitor);
    }
}
