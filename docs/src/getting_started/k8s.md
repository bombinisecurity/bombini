# Kubernetes

First pull `bombini` image:

```bash
docker pull ghcr.io/bombinisecurity/bombini:v1.1.0
```

`bombini.yaml` manifest has bombini ConfigMap with all configuration setup. By default, only ProcMon
detector is loaded. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md) chapter.

Besides the DaemonSet, the manifest creates a ServiceAccount with a ClusterRole allowing to watch pods,
and a FlowSchema limiting the load the agents put on kube-apiserver. Events are enriched with pod
metadata, see the [Kubernetes](../configuration/k8s.md) configuration chapter.

To start bombini DaemonSet run:

```bash
kubectl apply -f ./bombini.yaml
```

Events can be found in bombini k8s log.

## Kind Example

Pull `bombini` image:

```bash
docker pull ghcr.io/bombinisecurity/bombini:v1.1.0
```

Install [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation).

If your cwd is repo root change it to `./install/k8s`

```bash
cd ./install/k8s
```
Create kind cluster:

```bash
kind create cluster --config ./kind-config.yaml --name bombini-test-cluster
```

Load bombini image in kind cluster:

```bash
kind load docker-image bombini:latest --name bombini-test-cluster
```

Start bombini:

```bash
kubectl apply -f ./bombini.yaml
```

Check events:

```bash
kubectl get pods | grep "^bombini" | awk '{print $1}' | xargs kubectl logs -f
```
