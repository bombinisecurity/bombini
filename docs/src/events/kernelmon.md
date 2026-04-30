# KernelMon

**KernelEvent** represent a collection of events related to kernel modification/intergration.

## BpfMapCreate

Event is triggered when BPF map is created.

``` json
{
  "blocked": false,
  "kernel_event": {
    "key_size": 1024,
    "map_type": "BPF_MAP_TYPE_HASH",
    "max_entries": 4096,
    "name": "AT_exec_count",
    "type": "BpfMapCreate",
    "value_size": 8
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/kernelmon-f8c2496bd03fa01a",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "filename": "kernelmon-f8c2496bd03fa01a",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84403,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:04.228Z",
    "tid": 84403,
    "uid": 0
  },
  "process": {
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }",
    "auid": 1000,
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0Nzc6ODY5NDg2MjQ1NzU5MTkz",
    "filename": "bpftrace",
    "gid": 0,
    "parent_exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "pid": 84477,
    "ppid": 84403,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:11.264Z",
    "tid": 84477,
    "uid": 0
  },
  "rule": "KernelMonBpfMapCreateTest",
  "timestamp": "2026-04-30T11:43:17.578Z",
  "type": "KernelEvent"
}
```

## BpfMapAccess

Event is triggered when BPF map is accessed by userspace.

``` json
{
  "blocked": false,
  "kernel_event": {
    "access_mode": "O_RDWR",
    "id": 11702,
    "map_type": "BPF_MAP_TYPE_HASH",
    "name": "AT_exec_count",
    "type": "BpfMapAccess"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/kernelmon-f8c2496bd03fa01a",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "filename": "kernelmon-f8c2496bd03fa01a",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84403,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:04.228Z",
    "tid": 84403,
    "uid": 0
  },
  "process": {
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }",
    "auid": 1000,
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0Nzc6ODY5NDg2MjQ1NzU5MTkz",
    "filename": "bpftrace",
    "gid": 0,
    "parent_exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "pid": 84477,
    "ppid": 84403,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:11.264Z",
    "tid": 84477,
    "uid": 0
  },
  "rule": "KernelMonBpfMapTest",
  "timestamp": "2026-04-30T11:43:17.578Z",
  "type": "KernelEvent"
}
```

## BpfProgLoad

Event is triggered when BPF program is loaded into the kernel.

``` json
{
  "blocked": false,
  "kernel_event": {
    "name": "rawtracepoint_v",
    "prog_type": "BPF_PROG_TYPE_TRACING",
    "type": "BpfProgLoad"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/kernelmon-f8c2496bd03fa01a",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "filename": "kernelmon-f8c2496bd03fa01a",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84403,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:04.228Z",
    "tid": 84403,
    "uid": 0
  },
  "process": {
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }",
    "auid": 1000,
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0Nzc6ODY5NDg2MjQ1NzU5MTkz",
    "filename": "bpftrace",
    "gid": 0,
    "parent_exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "pid": 84477,
    "ppid": 84403,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:11.264Z",
    "tid": 84477,
    "uid": 0
  },
  "rule": "KernelMonBpfProgLoadTest",
  "timestamp": "2026-04-30T11:43:17.578Z",
  "type": "KernelEvent"
}
```

## BpfProgAccess

Event is triggered when BPF program is accessed by userspace.

``` json
{
  "blocked": false,
  "kernel_event": {
    "hook": "sched_process_exec",
    "id": 1657,
    "name": "rawtracepoint_v",
    "prog_type": "BPF_PROG_TYPE_TRACING",
    "type": "BpfProgAccess"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/kernelmon-f8c2496bd03fa01a",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "filename": "kernelmon-f8c2496bd03fa01a",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84403,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:04.228Z",
    "tid": 84403,
    "uid": 0
  },
  "process": {
    "args": "-v -e rawtracepoint:sched_process_exec { @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }",
    "auid": 1000,
    "binary_path": "/nix/store/z49imdq9s4w9syjpnsab1jdh4xaccymm-bpftrace/bin/bpftrace",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ0Nzc6ODY5NDg2MjQ1NzU5MTkz",
    "filename": "bpftrace",
    "gid": 0,
    "parent_exec_id": "ODQ0MDM6ODY5NDc5MjEwMDAwMDAw",
    "pid": 84477,
    "ppid": 84403,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:11.264Z",
    "tid": 84477,
    "uid": 0
  },
  "rule": "KernelMonBpfProgTest",
  "timestamp": "2026-04-30T11:43:17.579Z",
  "type": "KernelEvent"
}
```

Note: `hook` field is available for specific BPF program types. For example, for `BPF_PROG_TYPE_TRACING`, `BPF_PROG_TYPE_LSM` and some others.
