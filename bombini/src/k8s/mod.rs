//! Kubernetes pod metadata enrichment

// Pod watcher is added in a following commit
#![allow(dead_code)]

pub mod index;
pub mod podinfo;

use crate::metrics::{BombiniCounter, BombiniMetricServer, MetricRegister};

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
