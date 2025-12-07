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

# List of the detectors to load
detectors:
   - procmon
   #- filemon
   #- netmon
   #- io_uringmon
   #- gtfobins
```

To enable detectors loading you must put the detector name in config detectors section.

**NOTE**: YAML file with the same name plus ".yaml" suffix must exist in
the same directory with `config.yaml`.

## Bombini CLI Arguments

```
Ebpf-based agent for observability and security monitoring

Usage: bombini [OPTIONS]

Options:
      --bpf-objs <FILE>                Directory with bpf detector object files
      --maps-pin-path <FILE>           Path to pin bpf maps
      --event-map-size <VALUE>         Event map size (ring buffer size in bytes) default value: 65536
      --event-channel-size <VALUE>     Raw event channel size (number of event messages) default value: 64
      --procmon-proc-map-size <VALUE>  Procmon process map size default value: 8192
  -D, --detector <NAME>                Detector to load. Can be specified multiple times. Overrides the config
      --config-dir <DIR>               YAML config dir with global config and detector configs [default: /usr/local/lib/bombini/config]
      --event-log <FILE>               File path to save events
      --event-socket <FILE>            Unix socket path to send events
  -h, --help                           Print help
  -V, --version                        Print version
```

`--bpf-objs`, `--maps-pin-path`, `--event-map-size`, `--event-channel-size`, `detector` options can override corresponding config options.
`--event-log`, `--event-socket` can override default stdout json serialized events output.