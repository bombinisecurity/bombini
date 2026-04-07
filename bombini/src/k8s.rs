use anyhow::Result;
use kube::{
    api::{Api, ListParams},
    Client,
};
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::runtime::watcher::{self, Event};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use futures_util::StreamExt;

/// Where a container is running in the cluster.
#[derive(Clone, Debug)]
pub struct ContainerLocation {
    pub namespace: String,
    pub pod_name: String,
    pub node_name: Option<String>,
    pub container_name: Option<String>,
}

/// Resolver maps a container runtime ID to Pod/Node using an in-memory index
/// that is maintained by a background Pod watcher.
#[derive(Clone)]
pub struct K8sResolver {
    state: Arc<RwLock<ResolverState>>,
}

struct ResolverState {
    by_container_prefix: HashMap<String, ContainerLocation>,
    pod_to_prefixes: HashMap<String, Vec<String>>,
    negative_cache: HashMap<String, Instant>,
}

impl ResolverState {
    fn new() -> Self {
        Self {
            by_container_prefix: HashMap::new(),
            pod_to_prefixes: HashMap::new(),
            negative_cache: HashMap::new(),
        }
    }
}

impl K8sResolver {
    /// Создать клиент, подхватывая kube‑config из окружения (in‑cluster или ~/.kube/config).
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;
        let state = Arc::new(RwLock::new(ResolverState::new()));
        let resolver = Self {
            state: state.clone(),
        };

        // Initial bootstrap list: one API call at startup.
        {
            let pods: Api<Pod> = Api::all(client.clone());
            let pod_list = pods.list(&ListParams::default()).await?;
            let mut st = state.write().await;
            for pod in pod_list {
                apply_pod_state(&mut st, &pod);
            }
        }

        // Background watcher keeps the in-memory index fresh.
        tokio::spawn(async move {
            let pods: Api<Pod> = Api::all(client);
            let cfg = watcher::Config::default();
            let mut stream = watcher::watcher(pods, cfg).boxed();
            while let Some(ev) = stream.next().await {
                match ev {
                    Ok(Event::Apply(pod)) => {
                        let mut st = state.write().await;
                        apply_pod_state(&mut st, &pod);
                    }
                    Ok(Event::Delete(pod)) => {
                        let mut st = state.write().await;
                        drop_pod_state(&mut st, &pod);
                    }
                    Ok(Event::Init) => {
                        let mut st = state.write().await;
                        st.by_container_prefix.clear();
                        st.pod_to_prefixes.clear();
                        st.negative_cache.clear();
                    }
                    Ok(Event::InitApply(pod)) => {
                        let mut st = state.write().await;
                        apply_pod_state(&mut st, &pod);
                    }
                    Ok(Event::InitDone) => {}
                    Err(e) => {
                        log::warn!("Kubernetes watcher error: {e}");
                    }
                }
            }
        });

        Ok(resolver)
    }

    /// Найти Pod/Node по container ID (префикс ID, как у вас из eBPF/cgroup).
    ///
    /// `container_id_prefix` — то, что сейчас лежит в `Process.container_id`
    /// (у вас это обрезанный до ~31 символа ID контейнера).
    pub async fn find_container(
        &self,
        container_id_prefix: &str,
    ) -> Result<Option<ContainerLocation>> {
        if container_id_prefix.is_empty() {
            return Ok(None);
        }

        const NEGATIVE_TTL: Duration = Duration::from_secs(20);

        let now = Instant::now();
        {
            let st = self.state.read().await;

            // Fast path: exact prefix key.
            let lookup_key = index_key(container_id_prefix);
            if let Some(loc) = st.by_container_prefix.get(&lookup_key) {
                return Ok(Some(loc.clone()));
            }

            // For shorter prefixes do prefix-scan.
            if container_id_prefix.len() < 31 {
                if let Some((_, loc)) = st
                    .by_container_prefix
                    .iter()
                    .find(|(k, _)| k.starts_with(container_id_prefix))
                {
                    return Ok(Some(loc.clone()));
                }
            }

            if let Some(ts) = st.negative_cache.get(container_id_prefix) {
                if now.duration_since(*ts) < NEGATIVE_TTL {
                    return Ok(None);
                }
            }
        }

        {
            let mut st = self.state.write().await;
            st.negative_cache
                .insert(container_id_prefix.to_string(), now);
        }

        Ok(None)
    }
}

fn apply_pod_state(state: &mut ResolverState, pod: &Pod) {
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let name = pod.metadata.name.clone().unwrap_or_default();
    let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());
    let pod_key = format!("{ns}/{name}");

    // Remove stale keys for the same pod before re-adding.
    if let Some(prev_keys) = state.pod_to_prefixes.remove(&pod_key) {
        for key in prev_keys {
            state.by_container_prefix.remove(&key);
        }
    }

    let mut keys = Vec::new();
    if let Some(status) = &pod.status {
        if let Some(statuses) = &status.container_statuses {
            collect_statuses(
                &mut state.by_container_prefix,
                &mut keys,
                &ns,
                &name,
                node_name.as_deref(),
                statuses,
            );
        }
        if let Some(statuses) = &status.init_container_statuses {
            collect_statuses(
                &mut state.by_container_prefix,
                &mut keys,
                &ns,
                &name,
                node_name.as_deref(),
                statuses,
            );
        }
        if let Some(statuses) = &status.ephemeral_container_statuses {
            collect_statuses(
                &mut state.by_container_prefix,
                &mut keys,
                &ns,
                &name,
                node_name.as_deref(),
                statuses,
            );
        }
    }

    if !keys.is_empty() {
        state.pod_to_prefixes.insert(pod_key, keys);
    }
}

fn drop_pod_state(state: &mut ResolverState, pod: &Pod) {
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let name = pod.metadata.name.clone().unwrap_or_default();
    let pod_key = format!("{ns}/{name}");
    if let Some(keys) = state.pod_to_prefixes.remove(&pod_key) {
        for key in keys {
            state.by_container_prefix.remove(&key);
        }
    }
}

fn collect_statuses(
    index: &mut HashMap<String, ContainerLocation>,
    keys: &mut Vec<String>,
    ns: &str,
    pod_name: &str,
    node_name: Option<&str>,
    statuses: &[ContainerStatus],
) {
    for cs in statuses {
        if let Some(cid) = &cs.container_id {
            let full = cid.split("://").last().unwrap_or(cid);
            let key = index_key(full);
            let loc = ContainerLocation {
                namespace: ns.to_string(),
                pod_name: pod_name.to_string(),
                node_name: node_name.map(str::to_string),
                container_name: Some(cs.name.clone()),
            };
            index.insert(key.clone(), loc);
            keys.push(key);
        }
    }
}

fn index_key(container_id_or_prefix: &str) -> String {
    container_id_or_prefix.chars().take(31).collect()
}

