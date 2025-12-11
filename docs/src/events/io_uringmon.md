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
    "start_time": "2025-12-11T12:37:46.235Z",
    "cloned": false,
    "pid": 53256,
    "tid": 53256,
    "ppid": 53255,
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
  "parent": {
    "start_time": "2025-12-11T12:37:46.221Z",
    "cloned": true,
    "pid": 53255,
    "tid": 53255,
    "ppid": 53226,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent"
  },
  "opcode": "IORING_OP_CONNECT",
  "op_info": {
    "addr": "127.0.0.1",
    "port": 443
  },
  "timestamp": "2025-12-11T12:37:46.238Z"
}
```

## IORING_OP_OPENAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-11T12:37:46.235Z",
    "cloned": false,
    "pid": 53256,
    "tid": 53256,
    "ppid": 53255,
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
  "parent": {
    "start_time": "2025-12-11T12:37:46.221Z",
    "cloned": true,
    "pid": 53255,
    "tid": 53255,
    "ppid": 53226,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent"
  },
  "opcode": "IORING_OP_OPENAT",
  "op_info": {
    "path": "/etc/passwd",
    "access_flags": "O_RDONLY",
    "creation_flags": "O_LARGEFILE"
  },
  "timestamp": "2025-12-11T12:38:25.972Z"
}
```

## IORING_OP_STATX

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-11T12:37:46.235Z",
    "cloned": false,
    "pid": 53256,
    "tid": 53256,
    "ppid": 53255,
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
  "parent": {
    "start_time": "2025-12-11T12:37:46.221Z",
    "cloned": true,
    "pid": 53255,
    "tid": 53255,
    "ppid": 53226,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent"
  },
  "opcode": "IORING_OP_STATX",
  "op_info": {
    "path": "/usr/bin/."
  },
  "timestamp": "2025-12-11T12:38:48.557Z"
}
```

## IORING_OP_UNLINKAT

```json
{
  "type": "IOUringEvent",
  "process": {
    "start_time": "2025-12-11T12:37:46.235Z",
    "cloned": false,
    "pid": 53256,
    "tid": 53256,
    "ppid": 53255,
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
  "parent": {
    "start_time": "2025-12-11T12:37:46.221Z",
    "cloned": true,
    "pid": 53255,
    "tid": 53255,
    "ppid": 53226,
    "uid": 1000,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 0,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "./agent"
  },
  "opcode": "IORING_OP_UNLINKAT",
  "op_info": {
    "path": "/home/fedotoff/RingReaper/agent"
  },
  "timestamp": "2025-12-11T12:39:29.061Z"
}
```
