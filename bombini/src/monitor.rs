//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{Duration, Instant},
};

use std::convert::TryFrom;
use std::mem;
use std::sync::Arc;

use bombini_common::event::GenericEvent;

use crate::config::Config;
use crate::k8s::K8sResolver;
use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;

use serde_json;

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
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(config.options.event_channel_size.unwrap());
        let ring_buf = RingBuf::try_from(Map::RingBuf(
            aya::maps::MapData::from_pin(config.options.event_pin_path()).unwrap(),
        ))
        .unwrap();
        let mut last_gc = Instant::now();
        let gc_period: Duration = Duration::from_secs(config.options.gc_period.unwrap());
        let mut transmuters = TransmuterRegistry::new(config);

        // Initialize Kubernetes resolver (best-effort).
        let k8s_resolver = if config.options.k8s_api_access {
            match K8sResolver::new(
                config.options.k8s_pod_labels,
                config.options.k8s_pod_annotations,
            )
            .await
            {
                Ok(r) => Some(Arc::new(r)),
                Err(e) => {
                    log::warn!("Failed to initialize Kubernetes client: {e}");
                    None
                }
            }
        } else {
            None
        };

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
        tokio::spawn(async move {
            let k8s_resolver = k8s_resolver;
            while let Some(message) = rx.recv().await {
                if message.len() < mem::size_of::<GenericEvent>() {
                    log::debug!(
                        "Skipping short event message: {} bytes (need at least {})",
                        message.len(),
                        mem::size_of::<GenericEvent>()
                    );
                    continue;
                }
                let event = unsafe { message.as_ptr().cast::<GenericEvent>().read_unaligned() };
                let transmuted = transmuters.transmute(&event);
                if let Ok(mut data) = transmuted {
                    if let Some(resolver) = &k8s_resolver {
                        if let Ok(enriched) =
                            enrich_process_with_k8s(data, resolver.as_ref()).await
                        {
                            data = enriched;
                        }
                    }
                    if let Err(e) = transmitter.transmit(data).await {
                        log::warn!("Failed to transmit event: {}", e);
                    }
                } else {
                    log::debug!("{}", transmuted.err().unwrap());
                }

                if last_gc.elapsed() >= gc_period {
                    transmuters.retain_caches();
                    last_gc = Instant::now();
                }
            }
        });
    }
}

async fn enrich_process_with_k8s(
    data: Vec<u8>,
    resolver: &K8sResolver,
) -> Result<Vec<u8>, anyhow::Error> {
    // Быстрый фильтр: если в JSON вообще нет container_id, дальше не парсим.
    if !data_windows_contains(&data, b"container_id") {
        return Ok(data);
    }

    let mut value: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Ok(data),
    };

    let Some(process) = value.get_mut("process").and_then(|v| v.as_object_mut()) else {
        return Ok(data);
    };
    let Some(cid) = process
        .get("container_id")
        .and_then(|v| v.as_str())
        .and_then(valid_container_id_prefix)
    else {
        return Ok(data);
    };

    if let Some(loc) = resolver.find_container(cid).await? {
        apply_location_json(process, &loc);
        return Ok(serde_json::to_vec(&value)?);
    }

    Ok(data)
}

fn data_windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

fn valid_container_id_prefix(s: &str) -> Option<&str> {
    // We enrich only container-originated events.
    // Truncated IDs from eBPF are expected to be 31 chars and hex.
    if s.len() != 31 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        None
    } else {
        Some(s)
    }
}

fn apply_location_json(
    process: &mut serde_json::Map<String, serde_json::Value>,
    loc: &crate::k8s::ContainerLocation,
) {
    let mut pod = serde_json::Map::new();
    pod.insert(
        "namespace".to_string(),
        serde_json::Value::String(loc.namespace.clone()),
    );
    pod.insert("name".to_string(), serde_json::Value::String(loc.pod_name.clone()));
    if let Some(node) = &loc.node_name {
        pod.insert("node".to_string(), serde_json::Value::String(node.clone()));
    }
    if let Some(container) = &loc.container_name {
        pod.insert(
            "container".to_string(),
            serde_json::Value::String(container.clone()),
        );
    }
    if let Some(labels) = &loc.labels {
        pod.insert("labels".to_string(), serde_json::to_value(labels).unwrap_or_default());
    }
    if let Some(annotations) = &loc.annotations {
        pod.insert(
            "annotations".to_string(),
            serde_json::to_value(annotations).unwrap_or_default(),
        );
    }
    process.insert("pod".to_string(), serde_json::Value::Object(pod));
    process.remove("k8s_namespace");
    process.remove("k8s_pod");
    process.remove("k8s_node");
    process.remove("k8s_container");
}
