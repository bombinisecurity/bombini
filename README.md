# Bombini: eBPF-based Security Monitoring Agent

**Bombini** is an eBPF-based security agent written entirely in Rust using the [Aya](https://github.com/aya-rs/aya) library and built on LSM (Linux Security Module) BPF hooks. At its core, Bombini employs modular components called Detectors, each responsible for monitoring and reporting specific types of system events. 

## Getting Started

Please, check the compatibility [issues](./docs/src/compatibility.md) first.

The most convenient way now is to build container with Bombini:

```bash
git clone https://github.com/bombinisecurity/bombini.git && \
cd ./bombini && \
docker build  -t bombini .
```

### Run

You can easily run Bombini with this command:

```bash
docker run --pid=host --rm -it --privileged -v /sys/fs/bpf:/sys/fs/bpf bombini
```
By default Bombini sends event to stdout in JSON format and starts only `ProcMon` detector intercepting
process execs and exits. To customize your Bombini setup, please, follow the configuration [guide](docs/src/configuration/README.md)
and mount config directory to the container:

```bash
docker run --pid=host --rm -it --privileged -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf bombini
```

## Build

To build Bombini from source, please, follow build [guide](./docs/src/getting_started/build.md).