# KernelMon

Detector provides events related to kernel modification/intergration.
Supported LSM hooks:

* `bpf_map_create` hook is used to detect BPF map creation.
* `bpf_map` hook provides information about BPF map access by userspace. Hook is triggered when userspace tries to get eBPF map descriptor.
Descriptor could be used to read/write data from/to the map, pin it to the filesystem, inspect kernel metadata.
* `bpf_prog_load` hook is used to detect BPF program loading.
* `bpf_prog` hook provides information about BPF program access by userspace. Hook is triggered when userspace tries to get eBPF program descriptor.
Descriptor could be used to attach/detach program to/from the hook, pin it to the filesystem or inspect kernel metadata.


## Required Linux Kernel Version

6.2 or greater

## Config Description

Config represents a dictionary with supported LSM BPF file hooks:

* bpf_map_create
* bpf_map
* bpf_prog_load
* bpf_prog

For each file hook the following options are supported:

* `enabled` enables detection for current hook. False by default.

## Event Filtering

All hooks support event filtering and do not provide sandboxing for now.

### bpf_map_create

`bpf_map_create` supports the following filtering attributes:

* `name` - name of BPF map (16 bytes).
* `prefix` - prefix of BPF map name (first 16 bytes).
* `type` - type of BPF map. See [linux kernel](https://elixir.bootlin.com/linux/v6.11/source/include/uapi/linux/bpf.h#L964) for the list of supported types.

**Example**

```yaml
bpf_map_create:
  enabled: true
  rules:
  - rule: "BpfMapCreateTest"
    event: type == "BPF_MAP_TYPE_HASH" AND name == "AT_exec_count"
```

### bpf_map

`bpf_map` supports the following filtering attributes:

* `id`- id of BPF map.
* `name` - name of BPF map (16 bytes).
* `prefix` - prefix of BPF map name (first 16 bytes).
* `type` - type of BPF map. See [linux kernel](https://elixir.bootlin.com/linux/v6.11/source/include/uapi/linux/bpf.h#L964) for the list of supported types.

**Example**

```yaml
bpf_map:
  enabled: true
  rules:
  - rule: "KernelMonBpfMapTest"
    event: type == "BPF_MAP_TYPE_HASH" AND prefix == "AT_exec"
```

### bpf_prog_load

`bpf_prog_load` supports the following filtering attributes:

* `name` - name of BPF program (16 bytes).
* `prefix` - prefix of BPF program name (first 16 bytes).
* `type` - type of BPF program. See [linux kernel](https://elixir.bootlin.com/linux/v6.11/source/include/uapi/linux/bpf.h#L1024) for the list of supported types.

**Example**

```yaml
bpf_prog_load:
  enabled: true
  rules:
  - rule: "KernelMonBpfProgLoadTest"
    event: type == "BPF_PROG_TYPE_TRACING" AND prefix == "rawtracepoint"
```

### bpf_prog

`bpf_prog` supports the following filtering attributes:

* `id`- id of BPF program.
* `name` - name of BPF program (16 bytes).
* `prefix` - prefix of BPF program name (first 16 bytes).
* `type` - type of BPF program. See [linux kernel](https://elixir.bootlin.com/linux/v6.11/source/include/uapi/linux/bpf.h#L1024) for the list of supported types.

**Example**

```yaml
bpf_prog:
  enabled: true
  rules:
  - rule: "KernelMonBpfProgTest"
    event: type == "BPF_PROG_TYPE_TRACING" AND name == "rawtracepoint_v"
```
