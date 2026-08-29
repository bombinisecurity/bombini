//! Serializable Kubernetes pod metadata

use std::collections::BTreeMap;

use serde::Serialize;

/// Pod metadata for a single container
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PodInfo {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    /// Owner workload name: Deployment, DaemonSet, etc.
    pub workload: String,
    pub workload_kind: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<BTreeMap<String, String>>")
    )]
    pub labels: BTreeMap<String, String>,
    pub container: ContainerInfo,
}

/// Container metadata from pod status
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ContainerInfo {
    /// Truncated container id: the same form as Process::container_id
    pub id: String,
    pub name: String,
    pub image: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub image_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub started_at: String,
}

/// Derive workload from pod owner reference. ReplicaSet is mapped to the
/// Deployment it belongs to by stripping the pod-template hash.
pub fn workload_from_owner(kind: &str, name: &str) -> (String, String) {
    if kind == "ReplicaSet"
        && let Some((deployment, hash)) = name.rsplit_once('-')
        && !deployment.is_empty()
        && !hash.is_empty()
    {
        return ("Deployment".to_string(), deployment.to_string());
    }
    (kind.to_string(), name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8s_workload_from_replica_set() {
        assert_eq!(
            workload_from_owner("ReplicaSet", "nginx-7d8b49c96f"),
            ("Deployment".to_string(), "nginx".to_string())
        );
        assert_eq!(
            workload_from_owner("ReplicaSet", "my-app-web-5c7f9d"),
            ("Deployment".to_string(), "my-app-web".to_string())
        );
        // bare ReplicaSet without a hash suffix
        assert_eq!(
            workload_from_owner("ReplicaSet", "standalone"),
            ("ReplicaSet".to_string(), "standalone".to_string())
        );
    }

    #[test]
    fn k8s_workload_from_other_owners() {
        for kind in ["DaemonSet", "StatefulSet", "Job", "Node", "Pod"] {
            assert_eq!(
                workload_from_owner(kind, "some-name"),
                (kind.to_string(), "some-name".to_string())
            );
        }
    }
}
