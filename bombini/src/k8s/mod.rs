//! Kubernetes pod metadata enrichment

// Without the watcher the index has no writer and stays empty
#![cfg_attr(not(feature = "k8s"), allow(dead_code))]

pub mod index;
pub mod podinfo;
#[cfg(feature = "k8s")]
pub mod watcher;

use std::sync::Arc;

use crate::metrics::{BombiniCounter, BombiniGauge, BombiniMetricServer, MetricRegister};
use crate::options::K8sOptions;
use index::PodIndex;

/// Pod index and the watcher feeding it
pub struct K8s {
    pub index: Arc<PodIndex>,
    metrics: Arc<WatchMetrics>,
}

/// Start the pod watcher if kubernetes enrichment is enabled
pub async fn start(opts: &K8sOptions) -> Result<Option<K8s>, anyhow::Error> {
    if !opts.k8s_enabled {
        return Ok(None);
    }
    #[cfg(not(feature = "k8s"))]
    anyhow::bail!("k8s_enabled requires the agent to be built with the k8s feature");
    #[cfg(feature = "k8s")]
    {
        let k8s = K8s {
            index: Arc::new(PodIndex::new()),
            metrics: Arc::new(WatchMetrics::new()),
        };
        watcher::start(opts, k8s.index.clone(), k8s.metrics.clone()).await?;
        Ok(Some(k8s))
    }
}

/// Pod watcher counters
pub struct WatchMetrics {
    pub index_size: BombiniGauge,
    pub errors: BombiniCounter,
}

impl WatchMetrics {
    pub fn new() -> Self {
        Self {
            index_size: BombiniGauge::new(
                "bombini_k8s_pod_index_size",
                "Number of containers known to the pod index",
            ),
            errors: BombiniCounter::new("bombini_k8s_watch_errors", "Number of pod watch failures"),
        }
    }
}

impl Default for WatchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricRegister for K8s {
    fn register_metrics(&self, metric_server: &mut BombiniMetricServer) {
        metric_server.register(&self.metrics.index_size);
        metric_server.register(&self.metrics.errors);
    }
}

/// Pod enrichment counters
pub struct EnrichMetrics {
    pub hit: BombiniCounter,
    pub miss: BombiniCounter,
    pub deferred: BombiniCounter,
}

impl EnrichMetrics {
    pub fn new() -> Self {
        Self {
            hit: BombiniCounter::new(
                "bombini_k8s_enrich_hit",
                "Number of processes enriched with pod info",
            ),
            miss: BombiniCounter::new(
                "bombini_k8s_enrich_miss",
                "Number of containerized processes with unknown pod",
            ),
            deferred: BombiniCounter::new(
                "bombini_k8s_deferred_resolved",
                "Number of processes enriched after their pod appeared in the index",
            ),
        }
    }
}

impl Default for EnrichMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricRegister for EnrichMetrics {
    fn register_metrics(&self, metric_server: &mut BombiniMetricServer) {
        metric_server.register(&self.hit);
        metric_server.register(&self.miss);
        metric_server.register(&self.deferred);
    }
}
