# Kubernetes

First build `bombini` container and push it to you container registry:

```bash
docker build -t bombini .
```

`bombini.yaml` manifest has bombini ConfigMap with all configuration setup. By default, only ProcMon
detector is loaded. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md) chapter.

To start bombini DaemonSet run:

```bash
kubectl apply -f ./bombini.yaml
```

Events can be found in bombini k8s log.

## Kind Example

Build bombini:

```bash
docker build -t bombini .
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