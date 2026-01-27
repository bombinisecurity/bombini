use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub service_account: String,
    pub node_name: String,
}
