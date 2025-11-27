# Container

Clone Bombini:

```bash
git clone https://github.com/bombinisecurity/bombini.git
```

Build container with Bombini:

```bash
cd ./bombini && \
docker build  -t bombini .
```

## Run

You can easily run Bombini with this command:

```bash
docker run --pid=host --rm -it --privileged -v /sys/fs/bpf:/sys/fs/bpf bombini
```

By default Bombini sends event to stdout in JSON format and starts only `ProcMon` detector intercepting
process execs and exits. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md) chapter
and mount config directory to the container:

```bash
docker run --pid=host --rm -it --privileged -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf bombini
```

You can save event logs to the file:

```bash
docker run --pid=host --rm -it --privileged -v /tmp/bombini.log:/log/bombini.log -v /sys/fs/bpf:/sys/fs/bpf bombini --event-log /log/bombini.log
```

Or send them via unix socket:

```bash
docker run --pid=host --rm -it --privileged -v /tmp/bombini.sock:/log/bombini.sock -v /sys/fs/bpf:/sys/fs/bpf bombini --event-socket /log/bombini.sock
```
Bombini uses `env_logger` crate. To see agent logs pass `--env "RUST_LOG=info|debug"`to docker run. 
