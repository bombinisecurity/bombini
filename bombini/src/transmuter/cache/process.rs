//! Process cache holds Process information used by transmuters

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::k8s::{EnrichMetrics, index::PodIndex};
use crate::transmuter::process::Process;
use bombini_common::event::process::{ProcInfo, ProcessKey};

/// How long a process waits for its pod. containerStatuses are published only
/// after the container has started, so the first events have no pod yet.
const PENDING_POD_TTL: Duration = Duration::from_secs(60);

pub struct CachedProcess {
    pub process: Arc<Process>,
    pub exited: bool,
}

pub struct ProcessCache {
    processes: HashMap<ProcessKey, CachedProcess>,
    /// None if kubernetes enrichment is disabled
    pod_index: Option<Arc<PodIndex>>,
    metrics: Arc<EnrichMetrics>,
    /// containerized processes waiting for their pod
    pending: Vec<(ProcessKey, Instant)>,
    pod_generation: u64,
}

impl ProcessCache {
    pub fn with_capacity(
        capacity: usize,
        pod_index: Option<Arc<PodIndex>>,
        metrics: Arc<EnrichMetrics>,
    ) -> Self {
        Self {
            processes: HashMap::with_capacity(capacity),
            pod_index,
            metrics,
            pending: Vec::new(),
            pod_generation: 0,
        }
    }

    pub fn get(&self, key: &ProcessKey) -> Option<&CachedProcess> {
        self.processes.get(key)
    }

    pub fn get_mut(&mut self, key: &ProcessKey) -> Option<&mut CachedProcess> {
        self.processes.get_mut(key)
    }

    /// Transmute, enrich and cache a new Process
    pub fn new_process(&mut self, proc: &ProcInfo, parent_key: &ProcessKey) -> Arc<Process> {
        let key = ProcessKey {
            pid: proc.pid,
            start: proc.start,
        };
        let mut process = Process::new(proc, parent_key);

        if let Some(pod_index) = self.pod_index.as_ref()
            && !process.container_id.is_empty()
        {
            process.pod = pod_index.lookup(&process.container_id);
            if process.pod.is_some() {
                self.metrics.hit.inc();
            } else {
                self.metrics.miss.inc();
                self.pending.push((key, Instant::now()));
            }
        }

        let process = Arc::new(process);
        self.processes.insert(
            key,
            CachedProcess {
                process: process.clone(),
                exited: false,
            },
        );
        process
    }

    /// Enrich processes cached before their pod became known. Does nothing
    /// until the set of container ids in the index changes.
    pub fn resolve_pending(&mut self) {
        let Some(pod_index) = self.pod_index.as_ref() else {
            return;
        };
        let generation = pod_index.generation();
        if generation == self.pod_generation {
            return;
        }
        self.pod_generation = generation;

        let Self {
            processes,
            metrics,
            pending,
            ..
        } = self;
        pending.retain(|(key, _)| {
            let Some(cached) = processes.get_mut(key) else {
                return false;
            };
            let Some(pod) = pod_index.lookup(&cached.process.container_id) else {
                return true;
            };
            let mut process = (*cached.process).clone();
            process.pod = Some(pod);
            cached.process = Arc::new(process);
            metrics.deferred.inc();
            false
        });
    }

    pub fn retain(&mut self) {
        self.processes.retain(|_, p| !p.exited);
        let Self {
            processes, pending, ..
        } = self;
        pending.retain(|(key, since)| {
            processes.contains_key(key) && since.elapsed() < PENDING_POD_TTL
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k8s::podinfo::{ContainerInfo, PodInfo};
    use bombini_common::constants::{
        DOCKER_ID_LENGTH, MAX_ARGS_SIZE, MAX_FILE_PATH, MAX_FILENAME_SIZE, MAX_IMA_HASH_SIZE,
    };
    use bombini_common::event::process::{Capabilities, Cgroup, Cred, ImaHash, SecureExec};
    use std::collections::BTreeMap;

    const ID: &str = "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345678a";

    fn proc_info(pid: u32, cgroup_name: &str) -> ProcInfo {
        let mut name = [0u8; DOCKER_ID_LENGTH];
        name[..cgroup_name.len()].copy_from_slice(cgroup_name.as_bytes());
        ProcInfo {
            start: 1,
            prev_start: 0,
            creds: Cred {
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
                cap_inheritable: Capabilities::empty(),
                cap_permitted: Capabilities::empty(),
                cap_effective: Capabilities::empty(),
                secureexec: SecureExec::empty(),
            },
            cgroup: Cgroup {
                cgroup_id: 0,
                cgroup_name: name,
            },
            pid,
            tid: pid,
            ppid: 1,
            auid: 0,
            cloned: false,
            filename: [0u8; MAX_FILENAME_SIZE],
            binary_path: [0u8; MAX_FILE_PATH],
            args: [0u8; MAX_ARGS_SIZE],
            ima_hash: ImaHash {
                algo: 0,
                hash: [0u8; MAX_IMA_HASH_SIZE],
            },
            exited: false,
        }
    }

    fn pod_map(container_id: &str) -> HashMap<String, Arc<PodInfo>> {
        HashMap::from([(
            container_id.to_string(),
            Arc::new(PodInfo {
                namespace: "default".to_string(),
                name: "nginx-7d8b49c96f-x2klm".to_string(),
                uid: "1c2d3e4f".to_string(),
                workload: "nginx".to_string(),
                workload_kind: "Deployment".to_string(),
                labels: BTreeMap::new(),
                container: ContainerInfo {
                    id: container_id.to_string(),
                    name: "nginx".to_string(),
                    image: "nginx:1.29".to_string(),
                    image_id: String::new(),
                    started_at: String::new(),
                },
            }),
        )])
    }

    fn cache(pod_index: Arc<PodIndex>) -> ProcessCache {
        ProcessCache::with_capacity(8, Some(pod_index), Arc::new(EnrichMetrics::new()))
    }

    #[test]
    fn k8s_enrich_known_pod() {
        let index = Arc::new(PodIndex::new());
        index.replace(pod_map(&ID[..31]));
        let mut cache = cache(index);

        let process = cache.new_process(
            &proc_info(100, &format!("cri-containerd-{ID}.scope")),
            &ProcessKey { pid: 1, start: 0 },
        );
        assert_eq!(process.pod.as_ref().unwrap().workload, "nginx");
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn k8s_enrich_host_process() {
        let index = Arc::new(PodIndex::new());
        index.replace(pod_map(&ID[..31]));
        let mut cache = cache(index);

        let process = cache.new_process(
            &proc_info(100, "init.scope"),
            &ProcessKey { pid: 1, start: 0 },
        );
        assert!(process.pod.is_none());
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn k8s_enrich_deferred() {
        let index = Arc::new(PodIndex::new());
        let mut cache = cache(index.clone());

        let key = ProcessKey { pid: 100, start: 1 };
        let process = cache.new_process(
            &proc_info(100, &format!("cri-containerd-{ID}.scope")),
            &ProcessKey { pid: 1, start: 0 },
        );
        assert!(process.pod.is_none());
        assert_eq!(cache.pending.len(), 1);

        // pod is still unknown
        cache.resolve_pending();
        assert_eq!(cache.pending.len(), 1);

        index.replace(pod_map(&ID[..31]));
        cache.resolve_pending();
        assert!(cache.pending.is_empty());
        assert_eq!(
            cache.get(&key).unwrap().process.pod.as_ref().unwrap().name,
            "nginx-7d8b49c96f-x2klm"
        );
    }

    #[test]
    fn k8s_pending_dropped_with_exited_process() {
        let index = Arc::new(PodIndex::new());
        let mut cache = cache(index);

        let key = ProcessKey { pid: 100, start: 1 };
        cache.new_process(
            &proc_info(100, &format!("cri-containerd-{ID}.scope")),
            &ProcessKey { pid: 1, start: 0 },
        );
        assert_eq!(cache.pending.len(), 1);

        cache.get_mut(&key).unwrap().exited = true;
        cache.retain();
        assert!(cache.pending.is_empty());
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn k8s_enrichment_disabled() {
        let mut cache = ProcessCache::with_capacity(8, None, Arc::new(EnrichMetrics::new()));
        let process = cache.new_process(
            &proc_info(100, &format!("cri-containerd-{ID}.scope")),
            &ProcessKey { pid: 1, start: 0 },
        );
        assert!(process.pod.is_none());
        assert!(cache.pending.is_empty());
    }
}
