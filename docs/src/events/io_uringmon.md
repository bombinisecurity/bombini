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
    "start_time": "2025-11-23T14:23:17.055Z",
    "pid": 2319039,
    "tid": 2319039,
    "ppid": 148879,
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
  "timestamp": "2025-11-23T14:24:00.256Z"
}
```

## IORING_OP_OPENAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-11-23T14:26:43.264Z",
    "pid": 2321741,
    "tid": 2321741,
    "ppid": 2319814,
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
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/etc/passwd",
    "access_flags": "O_RDONLY",
    "creation_flags": "O_LARGEFILE"
  },
  "timestamp": "2025-11-23T14:27:17.862Z"
}
```

## IORING_OP_STATX

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-11-21T21:32:13.849Z",
    "pid": 2321741,
    "tid": 2321741,
    "ppid": 2319814,
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
  "opcode": "IORING_OP_STATX",
  "op_info": {
    "path": "/usr/bin/pkexec"
  },
  "timestamp": "2025-11-23T14:28:24.124Z"
}
```

## IORING_OP_UNLINKAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-11-21T21:32:13.849Z",
    "pid": 2321741,
    "tid": 2321741,
    "ppid": 2319814,
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
  "timestamp": "2025-11-23T14:28:40.236Z"
}
```