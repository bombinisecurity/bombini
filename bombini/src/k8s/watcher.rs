//! Pod watcher keeping the pod index in sync with kube-apiserver

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::{
    Api, Client, ResourceExt,
    runtime::{WatchStreamExt, watcher},
};

use super::{
    WatchMetrics,
    index::{PodIndex, truncate_cri_id},
    podinfo::{ContainerInfo, PodInfo, workload_from_owner},
};
use crate::options::K8sOptions;

/// Containers of the node's pods, keyed by pod uid
type Store = HashMap<String, Vec<(String, Arc<PodInfo>)>>;

pub async fn start(
    opts: &K8sOptions,
    index: Arc<PodIndex>,
    metrics: Arc<WatchMetrics>,
) -> Result<(), anyhow::Error> {
    let node = opts
        .k8s_node_name
        .clone()
        .or_else(|| std::env::var("NODE_NAME").ok());
    let Some(node) = node else {
        bail!("k8s_node_name is not set and NODE_NAME is not in the environment");
    };
    let labels: HashSet<String> = opts.k8s_pod_labels.iter().flatten().cloned().collect();
    let delay = Duration::from_secs(startup_delay(
        &node,
        opts.k8s_startup_jitter_sec.unwrap_or(0),
    ));

    let client = Client::try_default()
        .await
        .context("Failed to create kubernetes client")?;
    let api: Api<Pod> = Api::all(client);
    // The field selector is backed by a watch cache index, so the apiserver
    // serves it without scanning every pod in the cluster
    let config = watcher::Config::default()
        .fields(&format!("spec.nodeName={node}"))
        .streaming_lists();

    tokio::spawn(async move {
        tokio::time::sleep(delay).await;

        let mut store = Store::new();
        let mut staged: Option<Store> = None;
        let mut stream = Box::pin(watcher(api, config).default_backoff());

        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    log::warn!("Pod watch failed: {e}");
                    metrics.errors.inc();
                    continue;
                }
            };
            match event {
                watcher::Event::Init => staged = Some(Store::new()),
                watcher::Event::InitApply(pod) => {
                    insert(staged.as_mut().unwrap_or(&mut store), &pod, &labels)
                }
                watcher::Event::InitDone => {
                    if let Some(staged) = staged.take() {
                        store = staged;
                    }
                    publish(&store, &index, &metrics);
                }
                watcher::Event::Apply(pod) => {
                    insert(&mut store, &pod, &labels);
                    publish(&store, &index, &metrics);
                }
                watcher::Event::Delete(pod) => {
                    if let Some(uid) = pod.uid() {
                        store.remove(&uid);
                    }
                    publish(&store, &index, &metrics);
                }
            }
        }
    });

    Ok(())
}

fn insert(store: &mut Store, pod: &Pod, labels: &HashSet<String>) {
    let Some(uid) = pod.uid() else {
        return;
    };
    store.insert(uid, containers(pod, labels));
}

fn publish(store: &Store, index: &PodIndex, metrics: &WatchMetrics) {
    let pod_index: HashMap<String, Arc<PodInfo>> = store
        .values()
        .flatten()
        .map(|(id, pod)| (id.clone(), pod.clone()))
        .collect();
    metrics.index_size.set(pod_index.len() as i64);
    index.replace(pod_index);
}

/// Pod info per container. containerID is published only once the container
/// has started, so a pod may contribute nothing yet.
fn containers(pod: &Pod, labels: &HashSet<String>) -> Vec<(String, Arc<PodInfo>)> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };
    let (workload_kind, workload) = pod
        .owner_references()
        .first()
        .map(|o| workload_from_owner(&o.kind, &o.name))
        .unwrap_or_else(|| ("Pod".to_string(), pod.name_any()));
    let labels = selected_labels(pod, labels);

    [
        status.init_container_statuses.as_ref(),
        status.container_statuses.as_ref(),
        status.ephemeral_container_statuses.as_ref(),
    ]
    .into_iter()
    .flatten()
    .flatten()
    .filter_map(|c| {
        let id = truncate_cri_id(c.container_id.as_deref()?)?;
        let info = PodInfo {
            namespace: pod.namespace().unwrap_or_default(),
            name: pod.name_any(),
            uid: pod.uid().unwrap_or_default(),
            workload: workload.clone(),
            workload_kind: workload_kind.clone(),
            labels: labels.clone(),
            container: container_info(c, id.clone()),
        };
        Some((id, Arc::new(info)))
    })
    .collect()
}

/// Pod labels are unbounded in size, so by default none are copied. "*"
/// copies all of them, anything else is an allowlist of label names.
fn selected_labels(pod: &Pod, allowed: &HashSet<String>) -> BTreeMap<String, String> {
    if allowed.contains("*") {
        return pod
            .labels()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
    }
    pod.labels()
        .iter()
        .filter(|(name, _)| allowed.contains(*name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn container_info(status: &ContainerStatus, id: String) -> ContainerInfo {
    let started_at = status
        .state
        .as_ref()
        .and_then(|s| s.running.as_ref())
        .and_then(|r| r.started_at.as_ref())
        .map(|t| t.0.to_string())
        .unwrap_or_default();
    ContainerInfo {
        id,
        name: status.name.clone(),
        image: status.image.clone(),
        image_id: status.image_id.clone(),
        started_at,
    }
}

/// Deterministic per node delay before the initial list: a fleet wide restart
/// must not hit kube-apiserver at once.
fn startup_delay(node: &str, jitter_sec: u64) -> u64 {
    if jitter_sec == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    node.hash(&mut hasher);
    hasher.finish() % jitter_sec
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345678a";

    fn pod() -> Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": {
                "name": "nginx-7d8b49c96f-x2klm",
                "namespace": "default",
                "uid": "1c2d3e4f-0000-0000-0000-000000000001",
                "labels": {"app": "nginx", "pod-template-hash": "7d8b49c96f"},
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "nginx-7d8b49c96f",
                    "uid": "1c2d3e4f-0000-0000-0000-000000000002",
                }],
            },
            "status": {
                "containerStatuses": [{
                    "name": "nginx",
                    "image": "nginx:1.29",
                    "imageID": "docker.io/library/nginx@sha256:dead",
                    "containerID": format!("containerd://{ID}"),
                    "ready": true,
                    "restartCount": 0,
                    "state": {"running": {"startedAt": "2026-08-29T10:00:00Z"}},
                }, {
                    // not started yet
                    "name": "sidecar",
                    "image": "envoy:1.35",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                }],
            },
        }))
        .unwrap()
    }

    #[test]
    fn k8s_containers_from_pod() {
        let containers = containers(&pod(), &HashSet::from(["app".to_string()]));
        assert_eq!(containers.len(), 1);

        let (id, info) = &containers[0];
        assert_eq!(id, &ID[..31]);
        assert_eq!(info.namespace, "default");
        assert_eq!(info.name, "nginx-7d8b49c96f-x2klm");
        assert_eq!(info.workload_kind, "Deployment");
        assert_eq!(info.workload, "nginx");
        assert_eq!(
            info.labels,
            BTreeMap::from([("app".to_string(), "nginx".to_string())])
        );
        assert_eq!(info.container.id, ID[..31]);
        assert_eq!(info.container.name, "nginx");
        assert_eq!(info.container.image, "nginx:1.29");
        assert_eq!(info.container.started_at, "2026-08-29T10:00:00Z");
    }

    #[test]
    fn k8s_labels_are_dropped_without_allowlist() {
        let containers = containers(&pod(), &HashSet::new());
        assert!(containers[0].1.labels.is_empty());
    }

    #[test]
    fn k8s_wildcard_copies_all_labels() {
        let containers = containers(&pod(), &HashSet::from(["*".to_string()]));
        assert_eq!(
            containers[0].1.labels,
            BTreeMap::from([
                ("app".to_string(), "nginx".to_string()),
                ("pod-template-hash".to_string(), "7d8b49c96f".to_string()),
            ])
        );
    }

    #[test]
    fn k8s_startup_delay_is_deterministic() {
        assert_eq!(startup_delay("node-1", 30), startup_delay("node-1", 30));
        assert!(startup_delay("node-1", 30) < 30);
        assert_eq!(startup_delay("node-1", 0), 0);
    }
}
