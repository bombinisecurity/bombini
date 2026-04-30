# IOUringMon

For these IORING_OP's Bombini provides extra information:

* IORING_OP_OPENAT / IORING_OP_OPENAT2
* IORING_OP_STATX
* IORING_OP_UNLINKAT
* IORING_OP_CONNECT
* IORING_OP_ACCEPT

For other event types only opcode is provided.

## IORING_OP_CONNECT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2026-04-30T12:14:56.094Z",
    "cloned": false,
    "pid": 101235,
    "tid": 101235,
    "ppid": 101234,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "exec_id": "MTAxMjM1Ojg3MTM5MTA3NTYxMjM5MA",
    "parent_exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA"
  },
  "parent": {
    "start_time": "2026-04-30T12:14:56.080Z",
    "cloned": true,
    "pid": 101234,
    "tid": 101234,
    "ppid": 101219,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent",
    "exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA",
    "parent_exec_id": "MTAxMjE5Ojg3MTM4ODc3NzYyODAwNg"
  },
  "opcode": "IORING_OP_CONNECT",
  "op_info": {
    "addr": "127.0.0.1",
    "port": 443
  },
  "timestamp": "2026-04-30T12:14:56.094Z"
}
```

## IORING_OP_OPENAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2026-04-30T12:14:56.094Z",
    "cloned": false,
    "pid": 101235,
    "tid": 101235,
    "ppid": 101234,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "exec_id": "MTAxMjM1Ojg3MTM5MTA3NTYxMjM5MA",
    "parent_exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA"
  },
  "parent": {
    "start_time": "2026-04-30T12:14:56.080Z",
    "cloned": true,
    "pid": 101234,
    "tid": 101234,
    "ppid": 101219,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent",
    "exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA",
    "parent_exec_id": "MTAxMjE5Ojg3MTM4ODc3NzYyODAwNg"
  },
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/etc/passwd",
    "access_flags": "O_RDONLY",
    "creation_flags": "O_LARGEFILE"
  },
  "timestamp": "2026-04-30T12:16:20.665Z"
}
```

## IORING_OP_STATX

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2026-04-30T12:14:56.094Z",
    "cloned": false,
    "pid": 101235,
    "tid": 101235,
    "ppid": 101234,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "exec_id": "MTAxMjM1Ojg3MTM5MTA3NTYxMjM5MA",
    "parent_exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA"
  },
  "parent": {
    "start_time": "2026-04-30T12:14:56.080Z",
    "cloned": true,
    "pid": 101234,
    "tid": 101234,
    "ppid": 101219,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent",
    "exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA",
    "parent_exec_id": "MTAxMjE5Ojg3MTM4ODc3NzYyODAwNg"
  },
  "opcode": "IORING_OP_STATX",
  "op_info": {
    "path": "/usr/bin/python3"
  },
  "timestamp": "2026-04-30T12:16:43.607Z"
}
```

## IORING_OP_UNLINKAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2026-04-30T12:14:56.094Z",
    "cloned": false,
    "pid": 101235,
    "tid": 101235,
    "ppid": 101234,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": "",
    "exec_id": "MTAxMjM1Ojg3MTM5MTA3NTYxMjM5MA",
    "parent_exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA"
  },
  "parent": {
    "start_time": "2026-04-30T12:14:56.080Z",
    "cloned": true,
    "pid": 101234,
    "tid": 101234,
    "ppid": 101219,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent",
    "exec_id": "MTAxMjM0Ojg3MTM5MTA2MjE0MzMxOA",
    "parent_exec_id": "MTAxMjE5Ojg3MTM4ODc3NzYyODAwNg"
  },
  "opcode": "IORING_OP_UNLINKAT",
  "op_info": {
    "path": "/home/fedotoff/RingReaper/agent"
  },
  "timestamp": "2026-04-30T12:17:08.674Z"
}
```
