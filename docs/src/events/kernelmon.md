# KernelMon

**KernelEvent** represent a collection of events related to kernel modification/intergration.

## BpfMapCreate

Event is triggered when BPF map is created.

``` json
{
  "type": "KernelEvent",
  "process": {
    "start_time": "2026-04-03T10:14:59.269Z",
    "cloned": false,
    "pid": 8674,
    "tid": 8674,
    "ppid": 8656,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "bpftrace",
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }"
  },
  "parent": {
    "start_time": "2026-04-03T10:14:56.859Z",
    "cloned": false,
    "pid": 8656,
    "tid": 8656,
    "ppid": 8644,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "kernelmon-33e18a1d9b63fc77",
    "binary_path": "/home/lima.linux/bombini/target/release/deps/kernelmon-33e18a1d9b63fc77",
    "args": "test_6_2_kernel -q --show-output --test-threads 1"
  },
  "blocked": false,
  "kernel_event": {
    "type": "BpfMapCreate",
    "name": "AT_exec_count",
    "map_type": "BPF_MAP_TYPE_HASH",
    "key_size": 1024,
    "value_size": 8,
    "max_entries": 4096
  },
  "timestamp": "2026-04-03T10:15:00.989Z",
  "rule": "KernelMonBpfMapCreateTest"
}
```

## BpfMapAccess

Event is triggered when BPF map is accessed by userspace.

``` json
{
  "type": "KernelEvent",
  "process": {
    "start_time": "2026-04-03T10:14:59.269Z",
    "cloned": false,
    "pid": 8674,
    "tid": 8674,
    "ppid": 8656,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "bpftrace",
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }"
  },
  "parent": {
    "start_time": "2026-04-03T10:14:56.859Z",
    "cloned": false,
    "pid": 8656,
    "tid": 8656,
    "ppid": 8644,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "kernelmon-33e18a1d9b63fc77",
    "binary_path": "/home/lima.linux/bombini/target/release/deps/kernelmon-33e18a1d9b63fc77",
    "args": "test_6_2_kernel -q --show-output --test-threads 1"
  },
  "blocked": false,
  "kernel_event": {
    "type": "BpfMapAccess",
    "id": 1699,
    "name": "AT_exec_count",
    "map_type": "BPF_MAP_TYPE_HASH",
    "access_mode": "O_RDWR"
  },
  "timestamp": "2026-04-03T10:15:00.989Z",
  "rule": "KernelMonBpfMapTest"
}
```

## BpfProgLoad

Event is triggered when BPF program is loaded into the kernel.

``` json
{
  "type": "KernelEvent",
  "process": {
    "start_time": "2026-04-03T10:14:59.269Z",
    "cloned": false,
    "pid": 8674,
    "tid": 8674,
    "ppid": 8656,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "bpftrace",
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }"
  },
  "parent": {
    "start_time": "2026-04-03T10:14:56.859Z",
    "cloned": false,
    "pid": 8656,
    "tid": 8656,
    "ppid": 8644,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "kernelmon-33e18a1d9b63fc77",
    "binary_path": "/home/lima.linux/bombini/target/release/deps/kernelmon-33e18a1d9b63fc77",
    "args": "test_6_2_kernel -q --show-output --test-threads 1"
  },
  "blocked": false,
  "kernel_event": {
    "type": "BpfProgLoad",
    "name": "rawtracepoint_v",
    "prog_type": "BPF_PROG_TYPE_TRACING"
  },
  "timestamp": "2026-04-03T10:15:00.989Z",
  "rule": "KernelMonBpfProgLoadTest"
}
```

## BpfProgAccess

Event is triggered when BPF program is accessed by userspace.

``` json
{
  "type": "KernelEvent",
  "process": {
    "start_time": "2026-04-03T10:14:59.269Z",
    "cloned": false,
    "pid": 8674,
    "tid": 8674,
    "ppid": 8656,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "bpftrace",
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }"
  },
  "parent": {
    "start_time": "2026-04-03T10:14:56.859Z",
    "cloned": false,
    "pid": 8656,
    "tid": 8656,
    "ppid": 8644,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "kernelmon-33e18a1d9b63fc77",
    "binary_path": "/home/lima.linux/bombini/target/release/deps/kernelmon-33e18a1d9b63fc77",
    "args": "test_6_2_kernel -q --show-output --test-threads 1"
  },
  "blocked": false,
  "kernel_event": {
    "type": "BpfProgAccess",
    "id": 237,
    "name": "rawtracepoint_v",
    "prog_type": "BPF_PROG_TYPE_TRACING",
    "hook": "sched_process_exec"
  },
  "timestamp": "2026-04-03T10:15:00.989Z",
  "rule": "KernelMonBpfProgTest"
}
```

Note: `hook` field is available for specific BPF program types. For example, for `BPF_PROG_TYPE_TRACING`, `BPF_PROG_TYPE_LSM` and some others.
