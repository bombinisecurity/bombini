## IOUringMon

IOUring detector tracks SQE submitting using `io_uring_submit_req` tracepoint.
It provides events with the process information and `io_uring_op` opcode which process
submits.

Inspired by this [example](https://github.com/armosec/curing) and [post](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/).

### Required Linux Kernel Version

6.8 or greater

### Config

IOUringMon detector supports process allow/deny list for event filtering:

```yaml
process_fiter:
  uid:
    - 0
  euid:
    - 0
  binary:
    name:
      - nslookup
```

The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).

### Event

```json
{
  "type": "IOUringEvent",
  "process": {
    "pid": 739856,
    "tid": 739856,
    "ppid": 462192,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "program",
    "binary_path": "/home/fedotoff/curing/io_uring_example/program",
    "args": "",
    "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
  },
  "opcode": "IORING_OP_OPENAT",
  "flags": 8208,
  "timestamp": "2025-05-31T10:05:31.236Z"
}
```
