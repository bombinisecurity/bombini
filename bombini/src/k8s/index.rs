//! Container id keyed pod index

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;

use crate::k8s::podinfo::PodInfo;
use crate::transmuter::process::CONTAINER_ID_LENGTH;

/// Lock free container id to pod mapping. Readers are on the event hot path,
/// the pod watcher is the only writer.
pub struct PodIndex {
    snapshot: ArcSwap<HashMap<String, Arc<PodInfo>>>,
    /// Incremented when the set of known container ids changes
    generation: AtomicU64,
}

impl PodIndex {
    pub fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(HashMap::new()),
            generation: AtomicU64::new(0),
        }
    }

    pub fn lookup(&self, container_id: &str) -> Option<Arc<PodInfo>> {
        self.snapshot.load().get(container_id).cloned()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Publish a new snapshot. Generation is bumped only if the id set differs:
    /// kubelet patches pod status constantly and every bump forces a rescan of
    /// unresolved processes.
    pub fn replace(&self, pods: HashMap<String, Arc<PodInfo>>) {
        let changed = {
            let old = self.snapshot.load();
            pods.len() != old.len() || pods.keys().any(|id| !old.contains_key(id))
        };
        self.snapshot.store(Arc::new(pods));
        if changed {
            self.generation.fetch_add(1, Ordering::Release);
        }
    }
}

impl Default for PodIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert containerID from pod status (`containerd://<64 hex>`) into the
/// truncated form Process::container_id holds.
pub fn truncate_cri_id(container_id: &str) -> Option<String> {
    let id = container_id
        .split_once("://")
        .map_or(container_id, |(_, id)| id);
    let bytes = id.as_bytes();
    if bytes.len() < CONTAINER_ID_LENGTH
        || !bytes[..CONTAINER_ID_LENGTH]
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    Some(id[..CONTAINER_ID_LENGTH].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k8s::podinfo::ContainerInfo;
    use std::collections::BTreeMap;

    const ID: &str = "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345678a";

    fn pod(id: &str) -> Arc<PodInfo> {
        Arc::new(PodInfo {
            namespace: "default".to_string(),
            name: "nginx-7d8b49c96f-x2klm".to_string(),
            uid: "1c2d3e4f".to_string(),
            workload: "nginx".to_string(),
            workload_kind: "Deployment".to_string(),
            labels: BTreeMap::new(),
            container: ContainerInfo {
                id: id.to_string(),
                name: "nginx".to_string(),
                image: "nginx:1.29".to_string(),
                image_id: String::new(),
                started_at: String::new(),
            },
        })
    }

    fn index_of(ids: &[&str]) -> HashMap<String, Arc<PodInfo>> {
        ids.iter().map(|id| (id.to_string(), pod(id))).collect()
    }

    #[test]
    fn k8s_truncate_cri_id() {
        let expected = Some(ID[..CONTAINER_ID_LENGTH].to_string());
        assert_eq!(truncate_cri_id(&format!("containerd://{ID}")), expected);
        assert_eq!(truncate_cri_id(&format!("cri-o://{ID}")), expected);
        assert_eq!(truncate_cri_id(&format!("docker://{ID}")), expected);
        assert_eq!(truncate_cri_id(ID), expected);

        assert_eq!(truncate_cri_id(""), None);
        assert_eq!(truncate_cri_id("containerd://"), None);
        assert_eq!(
            truncate_cri_id(&format!("containerd://{}", &ID[..16])),
            None
        );
        assert_eq!(
            truncate_cri_id("containerd://not-a-hex-id-but-long-enough"),
            None
        );
    }

    #[test]
    fn k8s_index_lookup() {
        let index = PodIndex::new();
        assert!(index.lookup("a").is_none());

        index.replace(index_of(&["a", "b"]));
        assert_eq!(index.lookup("a").unwrap().container.id, "a");
        assert_eq!(index.lookup("b").unwrap().container.id, "b");
        assert!(index.lookup("c").is_none());

        index.replace(index_of(&["c"]));
        assert!(index.lookup("a").is_none());
        assert_eq!(index.lookup("c").unwrap().container.id, "c");
    }

    #[test]
    fn k8s_index_generation() {
        let index = PodIndex::new();
        assert_eq!(index.generation(), 0);

        index.replace(index_of(&["a"]));
        assert_eq!(index.generation(), 1);

        // status update without new container ids
        index.replace(index_of(&["a"]));
        assert_eq!(index.generation(), 1);

        index.replace(index_of(&["a", "b"]));
        assert_eq!(index.generation(), 2);

        index.replace(index_of(&["a"]));
        assert_eq!(index.generation(), 3);
    }
}
