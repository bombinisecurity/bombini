## IOUringMon

IOUring detector tracks SQE submitting using `io_uring_submit_req` tracepoint.

Inspired by:

1. [curing example](https://github.com/armosec/curing) and [post](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/).
2. [RingReaper example](https://github.com/MatheuZSecurity/RingReaper) and [post](https://matheuzsecurity.github.io/hacking/evading-linux-edrs-with-io-uring/).

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

For these IORING_OP's Bombini provides extra information:

* IORING_OP_OPENAT / IORING_OP_OPENAT2
* IORING_OP_STATX
* IORING_OP_UNNLINKAT
* IORING_OP_CONNECT
* IORING_OP_ACCEPT

### RingReaper events 

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-08-04T12:09:05.571Z",
    "pid": 398565,
    "tid": 398565,
    "ppid": 247132,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "container_id": ""
  },
  "opcode": "IORING_OP_CONNECT",
  "op_info": {
    "addr": "127.0.0.1",
    "port": 443
  },
  "timestamp": "2025-08-04T12:09:05.984Z"
}
```

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-08-04T12:09:25.131Z",
    "pid": 398565,
    "tid": 398565,
    "ppid": 247132,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "container_id": ""
  },
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/etc/passwd",
    "access_flags": "O_RDONLY",
    "creation_flags": "O_LARGEFILE"
  },
  "timestamp": "2025-08-04T12:09:25.424Z"
}
```

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-08-04T12:09:29.439Z",
    "pid": 398565,
    "tid": 398565,
    "ppid": 247132,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "container_id": ""
  },
  "opcode": "IORING_OP_STATX",
  "op_info": {
    "path": "/usr/bin/pkexec"
  },
  "timestamp": "2025-08-04T12:09:29.607Z"
}
```

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-08-04T12:09:50.803Z",
    "pid": 398565,
    "tid": 398565,
    "ppid": 247132,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "container_id": ""
  },
  "opcode": "IORING_OP_UNLINKAT",
  "op_info": {
    "path": "/home/fedotoff/RingReaper/agent"
  },
  "timestamp": "2025-08-04T12:09:50.913Z"
}
```

### Curing events

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-08-04T12:21:01.543Z",
    "pid": 408864,
    "tid": 408864,
    "ppid": 9790,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "program",
    "binary_path": "/home/fedotoff/curing/io_uring_example/program",
    "args": "",
    "container_id": ""
  },
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/tmp/shadow.pdf",
    "access_flags": "O_WRONLY",
    "creation_flags": "O_CREAT | O_TRUNC | O_LARGEFILE"
  },
  "timestamp": "2025-08-04T12:21:01.616Z"
}
```
