use std::sync::Arc;

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use log::debug;
use prometheus_client::{
    encoding::{EncodeMetric, MetricEncoder, text::encode},
    metrics::{MetricType, TypedMetric, counter::Counter, gauge::Gauge},
    registry::{Metric, Registry},
};
use tokio::sync::Mutex;

pub type Labels = Vec<(String, String)>;

pub trait BombiniMetricBound: Metric + TypedMetric + Default + Clone {}
impl<T: Metric + TypedMetric + Default + Clone> BombiniMetricBound for T {}

#[derive(Debug)]
/// Metric that can be registered in BombiniMetricServer
pub struct BombiniMetric<T: BombiniMetricBound> {
    /// Name of the metric
    name: String,
    /// Help text for the metric
    help: String,
    /// Inner metric type with labels
    prometheus_metric: LabeledMetric<T>,
}

impl<T: BombiniMetricBound> BombiniMetric<T> {
    pub fn new<P: Into<String>>(name: P, help: P) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            prometheus_metric: Default::default(),
        }
    }

    #[allow(unused)]
    pub fn add_label(&mut self, name: String, value: String) {
        self.prometheus_metric.labels.push((name, value));
    }
}

pub type BombiniCounter = BombiniMetric<Counter>;
#[allow(unused)]
pub type BombiniGauge = BombiniMetric<Gauge>;

impl BombiniCounter {
    pub fn set(&self, value: u64) {
        self.prometheus_metric
            .metric
            .inner()
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.prometheus_metric.metric.inc();
    }
}

#[derive(Debug, Default, Clone)]
/// Metric type with labels that can be encoded with prometheus client
struct LabeledMetric<T: BombiniMetricBound> {
    /// Labels for the metric
    labels: Labels,
    /// Inner metric type provided by prometheus client
    metric: T,
}

impl<T: BombiniMetricBound> EncodeMetric for LabeledMetric<T> {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        let family_encoder = encoder.encode_family(&self.labels)?;

        self.metric.encode(family_encoder)
    }

    fn metric_type(&self) -> MetricType {
        T::TYPE
    }
}

/// Application state for prometheus exporter
#[derive(Debug)]
pub struct AppState {
    pub registry: Registry,
}

#[derive(Default)]
/// Registry for Bombini metrics. It is used to register metrics and start prometheus exporter.
pub struct BombiniMetricServer {
    /// Common labels for all metrics
    labels: Labels,
    /// Inner prometheus client registry
    registry: Registry,
}

/// Allow structs to register metrics in BombiniMetricServer
pub trait MetricRegister {
    fn register_metrics(&self, metric_server: &mut BombiniMetricServer);
}

impl BombiniMetricServer {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(unused)]
    pub fn add_label(&mut self, name: String, value: String) {
        self.labels.push((name, value));
    }

    pub fn register<T: BombiniMetricBound>(&mut self, metric: &BombiniMetric<T>) {
        let mut labeled = metric.prometheus_metric.clone();
        labeled.labels.extend(self.labels.clone());

        self.registry.register(&metric.name, &metric.help, labeled);
    }

    pub fn register_metrics(&mut self, metrics: &dyn MetricRegister) {
        metrics.register_metrics(self);
    }

    pub async fn start_local_server(mut self, port: u16) -> Result<(), anyhow::Error> {
        let state = AppState {
            registry: std::mem::take(&mut self.registry),
        };

        let state = Arc::new(Mutex::new(state));

        let router = Router::new()
            .route("/metrics", axum::routing::get(metrics_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
            .await
            .with_context(|| "Error while starting prometheus exporter")?;

        tokio::spawn(async move {
            debug!("Prometheus node exporter is running at port: {port}");
            axum::serve(listener, router).await
        });

        Ok(())
    }
}

/// Handler for GET requests to /metrics endpoint
async fn metrics_handler(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let state = state.lock().await;
    let mut buffer = String::new();
    encode(&mut buffer, &state.registry).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Body::from(buffer))
        .unwrap()
}
