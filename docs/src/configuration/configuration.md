# Configuration

This chapter describes the way Bombini can be configured. Configuration is done by YAML config files.
Config files are stored in separate directory `./config` for example. In this directory `config.yaml`
file must exist. This file provides a global Bombini agent configuration, which can be overrided by cli arguments.
To load detectors in config directory detector config yaml's must be provided (e.g. `procmon.yaml`).
Configuration of detectors is considered in the next chapters.
Protobuf specification for detectors configs located in [reference](reference.md) chapter.

## Bombini Config

Bombini agent configuration is stored in `config.yaml`. The example of config.yaml provided bellow:

```yaml
# Global parameters for bombini agent.
# All paths must be full canonical or
# relative to this config file.
---
# Directory with bpf detector object files
bpf_objs: /usr/local/lib/bombini/bpf

# Path to pin bpf maps.
maps_pin_path: /sys/fs/bpf/bombini

# Event map size (ring buffer size in bytes)
event_map_size: 65536

# Raw event channel size (number of event messages)
event_channel_size: 64

# Procmon process map size
procmon_proc_map_size: 8192

# Retain Transmuters caches every <gc_period> sec
gc_period: 30

# Transmit events to log file
log_file: /var/log/bombini/bombini.log

# Log file size in MB
log_file_size: 10

# Number of log file rotations
log_file_rotations: 5

# Enable log file compression
log_file_compression: false

# Prometheus metric server port. This option enables metric server
metric_server_port: 9100

# Enrich events with kubernetes pod metadata.
# Requires the agent to be built with the k8s feature
k8s_enabled: false

# Node to watch pods on. Defaults to the NODE_NAME environment variable
#k8s_node_name: node-1

# Max delay before the initial pod list request in seconds
k8s_startup_jitter_sec: 30

# Pod labels to copy into events. All the others are dropped
#k8s_pod_labels:
#   - app.kubernetes.io/name

# List of the detectors to load
detectors:
   - procmon
   #- filemon
   #- netmon
   # -kernelmon
   #- io_uringmon
   #- sysenummon
```

To enable detectors loading you must put the detector name in config detectors section.

**NOTE**: YAML file with the same name plus ".yaml" suffix must exist in
the same directory with `config.yaml`.

## Bombini CLI Arguments

```
Ebpf-based agent for observability and security monitoring

Usage: bombini [OPTIONS]

Options:
  -t, --validate [<PATH>]              Validate detector configs and rules, then exit. Without PATH, checks the detectors enabled in --config-dir. PATH is a config dir or a single <detector>.yaml file: the detector name is taken from the file name
      --bpf-objs <FILE>                Directory with bpf detector object files
      --maps-pin-path <FILE>           Path to pin bpf maps
      --event-map-size <VALUE>         Event map size (ring buffer size in bytes)
      --event-channel-size <VALUE>     Raw event channel size (number of event messages)
      --procmon-proc-map-size <VALUE>  Procmon process map size
  -D, --detector <NAME>                Detector to load. Can be specified multiple times. Overrides the config
      --gc-period <SEC>                GC period for user mode caches in seconds
      --config-dir <DIR>               YAML config dir with global config and detector configs [default: /usr/local/lib/bombini/config]
      --log-file <FILE>                File path to save events
      --log-file-rotations <VALUE>     Number of rotated files to keep
      --log-file-size <VALUE>          Max size of rotated file in mb
      --log-file-compression           Enable compression for rotated files
      --event-socket <FILE>            Unix socket path to send events
      --metric-server-port <PORT>      Prometheus exporter port
      --k8s-enabled                    Enrich events with kubernetes pod metadata
      --k8s-node-name <NAME>           Node to watch pods on. Defaults to the NODE_NAME environment variable
      --k8s-startup-jitter-sec <SEC>   Max delay before the initial pod list request in seconds
      --k8s-pod-label <NAME>           Pod label to copy into events. Can be specified multiple times. Use "*" to copy all labels
  -h, --help                           Print help
  -V, --version                        Print version
```

`--bpf-objs`, `--maps-pin-path`, `--event-map-size`, `--event-channel-size`, `detector` options can override corresponding config options.
`--log-file`, `--event-socket` can override default stdout json serialized events output.
`--k8s-*` options are described in the [Kubernetes](k8s.md) chapter.

## Validating Configs

`bombini --validate` (`-t`) parses detector configs, expands macros and compiles
rules the same way the agent does on start, then exits. It runs in user space
only: root privileges and eBPF support are not required, so it can be used on a
developer machine or in CI.

```bash
# Detectors enabled in config.yaml of the default config dir (procmon is always checked)
bombini --validate
# Another config dir, `-D` overrides the detector list
bombini -t --config-dir ./config -D filemon
# All <detector>.yaml files of a dir, config.yaml is not needed
bombini -t ./config
# A single file, the detector name is the part of the file name before the first `-`
bombini -t examples/filemon-macros.yaml
```

Each checked file is reported on its own line. Errors go to stderr and the exit
code is `1` if any file is invalid.

```
config/procmon.yaml: ok
config/filemon.yaml: filemon: rule "bad" at 1:8: Unrecognized EOF found at 7
```

**NOTE**: with a `PATH`, `--config-dir` and `-D` are rejected. Options that matter
only for a running agent (`--bpf-objs`, `--log-file*`, `--event-socket`,
`--metric-server-port`, `--k8s-*` and so on) cannot be combined with `--validate`.
