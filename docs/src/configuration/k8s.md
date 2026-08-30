# Kubernetes

Every event already carries a `container_id`, but on a Kubernetes node that id alone
says nothing about the workload it belongs to. Bombini can watch pods on its own node
and add a `pod` object to the `process` and `parent` structures of every event.

Enrichment is compiled in with the `k8s` cargo feature:

```bash
cargo xtask build --release --features k8s
```

The container image and the release tarball are both built with it. An agent built
without the feature refuses to start with `k8s_enabled: true`.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `k8s_enabled` | `false` | Enable pod metadata enrichment |
| `k8s_node_name` | `NODE_NAME` env | Node to watch pods on |
| `k8s_startup_jitter_sec` | `30` | Max delay before the initial pod list request |
| `k8s_pod_labels` | empty | Pod labels to copy into events |

```yaml
k8s_enabled: true
k8s_startup_jitter_sec: 30
k8s_pod_labels:
   - app.kubernetes.io/name
```

Pod labels are unbounded in size, so none are copied by default: only the labels
listed in `k8s_pod_labels` end up in events. To copy all of them instead, set
`k8s_pod_labels: ["*"]` (`*` must be quoted, YAML treats a bare one as an alias).

## Event Example

```json
{
  "process": {
    "args": "-la",
    "binary_path": "/usr/bin/ls",
    "container_id": "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4",
    "filename": "ls",
    "pid": 12379,
    "pod": {
      "namespace": "default",
      "name": "nginx-7d8b49c96f-x2klm",
      "uid": "8f14e45f-ea8f-4bd1-8b2a-1f7c3d9e0a12",
      "workload": "nginx",
      "workload_kind": "Deployment",
      "labels": {
        "app.kubernetes.io/name": "nginx"
      },
      "container": {
        "id": "b6b2eb0c1d3f4a5e8c7d9f0a1b2c3d4",
        "name": "nginx",
        "image": "nginx:1.29",
        "image_id": "docker.io/library/nginx@sha256:...",
        "started_at": "2026-08-29T10:00:00Z"
      }
    }
  },
  "type": "ProcessExec"
}
```

`pod.container.id` is always equal to the event's `container_id`: the id from the pod
status is truncated exactly like the one extracted in eBPF. `workload` is derived from
the pod owner reference, a ReplicaSet is mapped to its Deployment. Processes outside a
container have no `pod` field.

## RBAC

The agent lists and watches pods, nothing else:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

`install/k8s/bombini.yaml` ships the ServiceAccount, the ClusterRole and the binding,
and passes the node name to the agent through the downward API:

```yaml
env:
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
```

## Load on kube-apiserver

A DaemonSet on a large cluster means one watch per node, and a rolling restart means
all of them start at once. The agent keeps its share small:

* pods are selected with a `spec.nodeName` field selector, which the apiserver serves
  from a dedicated watch cache index, so an agent sees only its own node's pods;
* the initial list is a streaming list served from the watch cache;
* the first request is delayed by `hash(node_name) % k8s_startup_jitter_sec` seconds,
  which spreads a fleet wide restart deterministically;
* the watch stream is restarted with an exponential backoff.

All of that is client side politeness. The enforced limit is API Priority and
Fairness: `install/k8s/bombini.yaml` ships a `FlowSchema` and a
`PriorityLevelConfiguration` bound to the agent's ServiceAccount, so the apiserver
caps what the whole fleet can take regardless of how the agents behave.

## Unresolved Pods

`containerID` appears in the pod status only after the container has started, so the
very first events of a new container can be emitted without a `pod` field. Such
processes stay in the process cache and are enriched as soon as their container id
shows up in the index, which means later events of the same process do carry the pod.
Events that were already sent are not resent: join them by `container_id` on the
collector side.

Enrichment can be observed through [metrics](../metrics.md).
