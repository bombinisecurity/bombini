# Metrics

There are 9 metrics that can be exported in OpenMetrics format. Metrics are enabled by providing `metric-server-port` option and exported to `localhost:metric-server-port/metrics` endpoint.

### Events exported
- **Name**: `bombini_user_events_exported_total`
- **Type**: counter
- **Unit**: number of events
- **Description**: The total number of events exported by Bombini.

### Errors in user space
- **Name**: `bombini_user_events_lost_total`
- **Type**: counter
- **Unit**: number of events
- **Description**: The total number of events lost in user space.

### Errors in eBPF
- **Name**: `bombini_bpf_events_lost_total`
- **Type**: counter
- **Unit**: number of events
- **Description**: The total number of events lost in eBPF.

### Events lost in eBPF
- **Name**: `bombini_bpf_events_ringbuf_lost_total`
- **Type**: counter
- **Unit**: number of events
- **Description**: The total number of events lost in eBPF due to ring buffer overflow.

The metrics below are exported only when [Kubernetes](configuration/k8s.md) pod enrichment is enabled.

### Pod index size
- **Name**: `bombini_k8s_pod_index_size`
- **Type**: gauge
- **Unit**: number of containers
- **Description**: The number of containers known to the pod index.

### Pod watch errors
- **Name**: `bombini_k8s_watch_errors_total`
- **Type**: counter
- **Unit**: number of failures
- **Description**: The total number of pod watch failures. Each one restarts the watch stream with a backoff.

### Enriched processes
- **Name**: `bombini_k8s_enrich_hit_total`
- **Type**: counter
- **Unit**: number of processes
- **Description**: The total number of processes enriched with pod info.

### Unresolved processes
- **Name**: `bombini_k8s_enrich_miss_total`
- **Type**: counter
- **Unit**: number of processes
- **Description**: The total number of containerized processes whose pod was not in the index. Right after start it grows until the initial pod list arrives.

### Deferred resolutions
- **Name**: `bombini_k8s_deferred_resolved_total`
- **Type**: counter
- **Unit**: number of processes
- **Description**: The total number of processes enriched later, when their container id appeared in the index.