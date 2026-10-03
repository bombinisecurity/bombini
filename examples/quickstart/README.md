# Quickstart

A minimal config that shows detection and in-kernel blocking:

* `procmon.yaml`: reports setuid to root and blocks exec of any binary from `/tmp`.
* `filemon.yaml`: reports reads of `/etc/shadow`.
* `netmon.yaml`: reports outbound connections to the cloud metadata service `169.254.169.254`,
  a common way to steal cloud credentials.
* `config.yaml`: loads these detectors and prints events to stdout as JSON lines.

Start Bombini from the repository root (the image is built for x86_64):

```bash
docker run --pid=host --rm -it --privileged \
  -v $PWD/examples/quickstart:/usr/local/lib/bombini/config:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/bombinisecurity/bombini:v1.1.0
```

Generate events in another terminal:

```bash
./examples/quickstart/trigger.sh
```

The exec from `/tmp` fails with `Operation not permitted`, and Bombini reports it with
`"blocked":true` and `"rule":"DenyExecFromTmp"`.
