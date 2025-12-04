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
    "start_time": "2025-12-04T07:30:11.462Z",
    "pid": 2230188,
    "tid": 2230188,
    "ppid": 2230022,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": ""
  },
  "opcode": "IORING_OP_CONNECT",
  "op_info": {
    "addr": "127.0.0.1",
    "port": 443
  },
  "timestamp": "2025-12-04T07:30:11.463Z"
}
```

## IORING_OP_OPENAT

```json

{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-04T07:37:58.995Z",
    "pid": 2238307,
    "tid": 2238307,
    "ppid": 2238306,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": ""
  },
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/etc/passwd",
    "access_flags": "O_RDONLY",
    "creation_flags": "O_LARGEFILE"
  },
  "timestamp": "2025-12-04T07:38:05.465Z"
}

```

## IORING_OP_STATX

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-04T07:37:58.995Z",
    "pid": 2238307,
    "tid": 2238307,
    "ppid": 2238306,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": ""
  },
  "opcode": "IORING_OP_STATX",
  "op_info": {
    "path": "/usr/bin/pkexec"
  },
  "timestamp": "2025-12-04T07:38:12.291Z"
}
```

## IORING_OP_UNLINKAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-04T07:30:12.039Z",
    "pid": 2230188,
    "tid": 2230188,
    "ppid": 2230022,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "agent",
    "binary_path": "/home/fedotoff/RingReaper/agent",
    "args": ""
  },
  "opcode": "IORING_OP_UNLINKAT",
  "op_info": {
    "path": "/home/fedotoff/RingReaper/agent"
  },
  "timestamp": "2025-12-04T07:33:12.647Z"
}
```
