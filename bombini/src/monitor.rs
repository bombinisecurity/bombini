//! Monitor module collects raw events from ring buffer.

use aya::maps::{Map, RingBuf};

use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{Duration, Instant},
};

use std::convert::TryFrom;
use std::sync::Arc;

use bombini_common::event::GenericEvent;

use crate::config::Config;
use crate::k8s::K8sResolver;
use crate::transmitter::Transmitter;
use crate::transmuter::TransmuterRegistry;
use crate::transmuter::process::{ProcessClone, ProcessExec, ProcessExit};

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
        let k8s_resolver = match K8sResolver::new().await {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                log::warn!("Failed to initialize Kubernetes client: {e}");
                None
            }
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
                let event: &GenericEvent = unsafe { &*message.as_ptr().cast::<GenericEvent>() };
                let transmuted = transmuters.transmute(event);
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

    // Порядок: наиболее частые и простые события.
    if let Ok(mut ev) = serde_json::from_slice::<ProcessExec>(&data) {
        if let Some(cid) = non_empty(&ev.process.container_id) {
            if let Some(loc) = resolver.find_container(cid).await? {
                apply_location(&mut ev.process, &loc);
                return Ok(serde_json::to_vec(&ev)?);
            }
        }
        return Ok(data);
    }

    if let Ok(mut ev) = serde_json::from_slice::<ProcessClone>(&data) {
        if let Some(cid) = non_empty(&ev.process.container_id) {
            if let Some(loc) = resolver.find_container(cid).await? {
                apply_location(&mut ev.process, &loc);
                return Ok(serde_json::to_vec(&ev)?);
            }
        }
        return Ok(data);
    }

    if let Ok(mut ev) = serde_json::from_slice::<ProcessExit>(&data) {
        if let Some(cid) = non_empty(&ev.process.container_id) {
            if let Some(loc) = resolver.find_container(cid).await? {
                apply_location(&mut ev.process, &loc);
                return Ok(serde_json::to_vec(&ev)?);
            }
        }
        return Ok(data);
    }

    // Для ProcessEvent (LSM хуки) у нас нет отдельного типа наружу, поэтому
    // здесь пока ничего не делаем; при необходимости можно добавить десериализацию
    // аналогично остальным структурам.

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

fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn apply_location(proc: &mut crate::transmuter::process::Process, loc: &crate::k8s::ContainerLocation) {
    proc.k8s_namespace = Some(loc.namespace.clone());
    proc.k8s_pod = Some(loc.pod_name.clone());
    proc.k8s_node = loc.node_name.clone();
    proc.k8s_container = loc.container_name.clone();
}
