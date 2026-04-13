use std::{path::Path, sync::Arc};

use aya::maps::{Map, PerCpuArray};

use crate::metrics::{self, BombiniCounter};

const BOMBINI_BPF_ERROR_SCRAPING_INTERVAL_SEC: u64 = 1;

#[derive(Debug)]
pub(super) struct BpfErrorsMonitor {
    events_lost_total: Arc<BombiniCounter>,
    events_ringbuf_lost_total: Arc<BombiniCounter>,
}

impl BpfErrorsMonitor {
    pub fn new() -> Self {
        Self {
            events_lost_total: Arc::new(BombiniCounter::new(
                "bombini_bpf_events_lost",
                "Total number of events lost in bpf",
            )),
            events_ringbuf_lost_total: Arc::new(BombiniCounter::new(
                "bombini_bpf_events_ringbuf_lost",
                "Total number of bpf events lost due to ring buffer overflow",
            )),
        }
    }

    pub async fn monitor_errors<P: AsRef<Path>>(
        &self,
        maps_pin_path: P,
    ) -> Result<(), anyhow::Error> {
        let errors_total: PerCpuArray<_, u64> = PerCpuArray::try_from(Map::PerCpuArray(
            aya::maps::MapData::from_pin(maps_pin_path.as_ref().join("BOMBINI_BPF_ERRORS_TOTAL"))
                .unwrap(),
        ))?;
        let events_lost_total: PerCpuArray<_, u64> = PerCpuArray::try_from(Map::PerCpuArray(
            aya::maps::MapData::from_pin(
                maps_pin_path.as_ref().join("BOMBINI_BPF_EVENTS_LOST_TOTAL"),
            )
            .unwrap(),
        ))?;
        let errors_total_metric = self.events_lost_total.clone();
        let events_lost_total_metric = self.events_ringbuf_lost_total.clone();
        tokio::spawn(async move {
            loop {
                let errors: u64 = errors_total.get(&0, 0).unwrap().iter().sum();
                let events_lost: u64 = events_lost_total.get(&0, 0).unwrap().iter().sum();
                errors_total_metric.set(errors);
                events_lost_total_metric.set(events_lost);
                tokio::time::sleep(std::time::Duration::from_secs(
                    BOMBINI_BPF_ERROR_SCRAPING_INTERVAL_SEC,
                ))
                .await;
            }
        });

        Ok(())
    }
}

impl metrics::MetricRegister for BpfErrorsMonitor {
    fn register_metrics(&self, registry: &mut metrics::BombiniMetricServer) {
        registry.register(&*self.events_lost_total);
        registry.register(&*self.events_ringbuf_lost_total);
    }
}
