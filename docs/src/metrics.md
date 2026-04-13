# Metrics

There are 4 metrics that can be exported in OpenMetrics format. Metrics are enabled by providing `metric-server-port` option and exported to `localhost:metric-server-port/metrics` endpoint.

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