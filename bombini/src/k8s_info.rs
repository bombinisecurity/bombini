use log;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use k8s_openapi::api::core::v1::Pod;
use kube::{
    Client, Config,
    api::{Api, ListParams},
};
use tokio::time::{self, Duration};

use bombini_common::k8s::PodInfo;

async fn initialize_k8s_client() -> Result<kube::Client, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(client) = kube::Client::try_default().await {
        return Ok(client);
    }

    match Config::incluster() {
        Ok(cfg) => match kube::Client::try_from(cfg) {
            Ok(client) => Ok(client),
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        },
        Err(_) => {
            let err = kube::Client::try_default().await.err().unwrap();
            Err(Box::new(err))
        }
    }
}

#[derive(Clone)]
pub struct K8sInfo {
    pods: Arc<RwLock<HashMap<String, PodInfo>>>,
    k8s_available: Arc<std::sync::atomic::AtomicBool>,
}

impl K8sInfo {
    pub async fn new() -> Self {
        let pods = Arc::new(RwLock::new(HashMap::new()));
        let k8s_available = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let k8s_info = K8sInfo {
            pods: pods.clone(),
            k8s_available: k8s_available.clone(),
        };

        let client_result = match initialize_k8s_client().await {
            Ok(client) => {
                log::info!("Successfully connected to Kubernetes");
                Ok(client)
            }
            Err(e) => {
                log::warn!("Failed to connect using default configuration: {}", e);
                Err(e)
            }
        };

        if client_result.is_ok() {
            k8s_available.store(true, std::sync::atomic::Ordering::Relaxed);

            let k8s_info_clone = k8s_info.clone();
            tokio::spawn(async move {
                if let Err(e) = k8s_info_clone.watch_pods().await {
                    log::error!("watching pods failed: {}", e);
                }
            });
        } else {
            log::warn!("Kubernetes client not available, pod monitoring disabled");
        }

        k8s_info
    }

    pub fn get_pod_info(&self, container_id: &str) -> Option<PodInfo> {
        if self
            .k8s_available
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let pods = self.pods.read().unwrap();
            let result = pods.get(container_id).cloned();
            result
        } else {
            None
        }
    }

    async fn watch_pods(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::try_default().await?;
        let pods: Api<Pod> = Api::all(client);
        let lp = ListParams::default();

        loop {
            match pods.list(&lp).await {
                Ok(pod_list) => {
                    let mut locked_pods = self.pods.write().unwrap();
                    locked_pods.clear();

                    for pod in pod_list {
                        if let Some(status) = pod.status {
                            if let Some(container_statuses) = status.container_statuses {
                                for container_status in &container_statuses {
                                    if let Some(id) = &container_status.container_id {
                                        let trimmed_id = id
                                            .trim_start_matches("cri-o://")
                                            .trim_start_matches("containerd://")
                                            .trim_start_matches("docker://");
                                        log::debug!(
                                            "Processing container ID: {} -> {} for pod {}/{}",
                                            id,
                                            trimmed_id,
                                            pod.metadata.namespace.as_deref().unwrap_or("default"),
                                            pod.metadata.name.as_deref().unwrap_or("<no-name>")
                                        );

                                        let pod_info = PodInfo {
                                            name: pod.metadata.name.clone().unwrap_or_default(),
                                            namespace: pod
                                                .metadata
                                                .namespace
                                                .clone()
                                                .unwrap_or_default(),
                                            service_account: pod
                                                .spec
                                                .as_ref()
                                                .unwrap()
                                                .service_account_name
                                                .clone()
                                                .unwrap_or_default(),
                                            node_name: pod
                                                .spec
                                                .as_ref()
                                                .unwrap()
                                                .node_name
                                                .clone()
                                                .unwrap_or_default(),
                                        };
                                        locked_pods.insert(trimmed_id.to_string(), pod_info);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("failed to list pods: {}", e);
                }
            }
            time::sleep(Duration::from_secs(60)).await;
        }
    }
}
