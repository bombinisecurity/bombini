## IOUringMon

IOUring detector tracks SQE submitting using `io_uring_submit_req` tracepoint.
It provides events with the process information and `io_uring_op` opcode which process
submits.

Inspired by this [example](https://github.com/armosec/curing) and [post](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/).

### Config

This detector has no config

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
    "args": ""
  },
  "opcode": "IORING_OP_OPENAT",
  "flags": 8208,
  "timestamp": "2025-05-31T10:05:31.236Z"
}
```
