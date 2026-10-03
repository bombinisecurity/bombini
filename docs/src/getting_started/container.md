# Container

Download Bombini container image:

```bash
docker pull ghcr.io/bombinisecurity/bombini:v1.1.0
```

## Run

You can easily run Bombini with this command:

```bash
docker run --pid=host --rm -it --privileged -v /sys/fs/bpf:/sys/fs/bpf ghcr.io/bombinisecurity/bombini:v1.1.0
```

By default Bombini sends event to stdout in JSON format and starts only `ProcMon` detector intercepting
process execs and exits. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md) chapter
and mount config directory to the container:

```bash
docker run --pid=host --rm -it --privileged -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf ghcr.io/bombinisecurity/bombini:v1.1.0
```

You can save event logs to the file:

```bash
docker run --pid=host --rm -it --privileged -v /tmp/bombini:/log -v /sys/fs/bpf:/sys/fs/bpf ghcr.io/bombinisecurity/bombini:v1.1.0 --event-log /log/bombini.log
```

Or send them via unix socket. Bombini connects to the socket as a client, so start a listener first:

```bash
mkdir -p /tmp/bombini && socat UNIX-LISTEN:/tmp/bombini/bombini.sock,fork -
```

```bash
docker run --pid=host --rm -it --privileged -v /tmp/bombini:/log -v /sys/fs/bpf:/sys/fs/bpf ghcr.io/bombinisecurity/bombini:v1.1.0 --event-socket /log/bombini.sock
```

Bombini uses `env_logger` crate. To see agent logs pass `--env "RUST_LOG=info|debug"` to docker run.
