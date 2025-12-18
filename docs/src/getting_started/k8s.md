# Kubernetes

First build `bombini-builder` container and push it to you container registry:

```bash
cd ./install/k8s/ && docker build -t bombini-builder .
```
This container has all deps for building bombini on the node with no need of internet.

`bombini.yaml` manifest has bombini ConfigMap with all configuration setup. By default, only ProcMon
detector is loaded. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md) chapter.

To start bombini DaemonSet run:

```bash
kubectl apply -f ./bombini.yaml
```

Events can be found in bombini k8s log.

## Kind Example

Install [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation).

If your cwd is repo root change it to `./install/k8s`

```bash
cd ./install/k8s
```
Create kind cluster:

```bash
kind create cluster --config ./kind-config.yaml --name bombini-test-cluster 
```

Build bombini-builder:

```bash
docker build -t bombini-builder .
```

Load bombini-builder image in kind cluster:

```bash
kind load docker-image bombini-builder:latest --name bombini-test-cluster
```

Start bombini:

```bash
kubectl apply -f ./bombini.yaml
```

