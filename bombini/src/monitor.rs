//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::{
    io::unix::AsyncFd,
    sync::mpsc::{self, error::TrySendError},
    time::{Duration, Instant, MissedTickBehavior, interval_at},
};

use std::{
    convert::TryFrom,
    mem::{MaybeUninit, size_of},
    path::PathBuf,
    sync::Arc,
};

use bombini_common::event::GenericEvent;

use crate::k8s::{EnrichMetrics, index::PodIndex};
use crate::metrics::BombiniCounter;
use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;
use crate::{config::Config, metrics};

mod bpf_errors;

pub struct Monitor {
    events_exported_total: Arc<BombiniCounter>,
    userspace_events_lost: Arc<BombiniCounter>,
    enrich_metrics: Arc<EnrichMetrics>,
    /// None if kubernetes enrichment is disabled
    pod_index: Option<Arc<PodIndex>>,
    bpf_errors_monitor: bpf_errors::BpfErrorsMonitor,
}

impl Monitor {
    pub fn new(pod_index: Option<Arc<PodIndex>>) -> Self {
        Self {
            events_exported_total: Arc::new(BombiniCounter::new(
                "bombini_user_events_exported",
                "Number of events exported",
            )),
            userspace_events_lost: Arc::new(BombiniCounter::new(
                "bombini_user_events_lost",
                "Number of events lost in user space",
            )),
            enrich_metrics: Arc::new(EnrichMetrics::new()),
            pod_index,
            bpf_errors_monitor: bpf_errors::BpfErrorsMonitor::new(),
        }
    }

    /// Counter of events lost in user space, for transmitters that drop events
    /// outside the `transmit` call (e.g. the file log thread).
    pub fn events_lost_counter(&self) -> Arc<BombiniCounter> {
        self.userspace_events_lost.clone()
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
        let (tx, mut rx) = mpsc::channel::<Box<MaybeUninit<GenericEvent>>>(
            config.options.event_channel_size.unwrap(),
        );
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(config.options.event_pin_path()).unwrap(),
        ))
        .unwrap();
        let gc_period: Duration = Duration::from_secs(config.options.gc_period.unwrap());
        let mut transmuters =
            TransmuterRegistry::new(config, self.pod_index.clone(), self.enrich_metrics.clone());

        // Start bpf errors monitor
        let maps_pin_path = PathBuf::from(config.options.maps_pin_path.as_ref().unwrap());
        self.bpf_errors_monitor
            .monitor_errors(maps_pin_path)
            .await
            .unwrap();

        let ring_buf_events_lost = self.userspace_events_lost.clone();
        tokio::spawn(async move {
            let mut poll = AsyncFd::new(ring_buf).unwrap();
            loop {
                let mut guard = poll.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    // Allocating fresh memory for proper struct alignment
                    let mut event = Box::new(MaybeUninit::<GenericEvent>::uninit());
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            item.as_ptr(),
                            event.as_mut_ptr().cast::<u8>(),
                            size_of::<GenericEvent>(),
                        );
                    }
                    match tx.try_send(event) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            ring_buf_events_lost.inc();
                        }
                        Err(TrySendError::Closed(_)) => {
                            log::error!("Stopped reading events: channel closed");
                            return;
                        }
                    }
                }
                guard.clear_ready();
            }
        });
        let events_exported_metric = self.events_exported_total.clone();
        let userspace_events_lost = self.userspace_events_lost.clone();
        tokio::spawn(async move {
            let mut gc_interval = interval_at(Instant::now() + gc_period, gc_period);
            gc_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;

                    _ = gc_interval.tick() => {
                        transmuters.retain_caches();
                    }
                    message = rx.recv() => {
                        let Some(message) = message else {
                            break;
                        };
                        let event = unsafe { message.assume_init_ref() };
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
                    }
                }
            }
        });
    }
}

impl metrics::MetricRegister for Monitor {
    fn register_metrics(&self, registry: &mut metrics::BombiniMetricServer) {
        registry.register(&*self.events_exported_total);
        registry.register(&*self.userspace_events_lost);
        registry.register_metrics(&*self.enrich_metrics);
        registry.register_metrics(&self.bpf_errors_monitor);
    }
}
