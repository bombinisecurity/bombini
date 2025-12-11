# NetMon

NetworkEvent represents a collection of events which
describe ingress/egress TCP connections over ipv4/v6.

## TcpConnectionEstablish

Example: `wget -qO- -6 google.com`

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-12-11T12:31:24.089Z",
    "cloned": false,
    "pid": 47663,
    "tid": 47663,
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
    "filename": "wget",
    "binary_path": "/usr/bin/wget",
    "args": "-qO- -6 google.com"
  },
  "parent": {
    "start_time": "2025-12-04T07:30:11.663Z",
    "cloned": false,
    "pid": 2230022,
    "tid": 2230022,
    "ppid": 72741,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "zsh",
    "binary_path": "/usr/bin/zsh",
    "args": ""
  },
  "network_event": {
    "type": "TcpConnectionEstablish",
    "saddr": "2a00:1370:81a6:3f56:35f:ba59:506b:7d59",
    "daddr": "2a00:1450:4001:80f::200e",
    "sport": 44538,
    "dport": 80,
    "cookie": 63
  },
  "timestamp": "2025-12-11T12:31:24.105Z"
}
```

Example:
```bash
nc -l 7878
telnet localhost 7878
```

```json
{
  "network_event": {
    "cookie": 49184,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 49856,
    "type": "TcpConnectionEstablish"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "localhost 7878",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "inetutils-telnet",
    "gid": 0,
    "pid": 6961,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:59.923Z",
    "tid": 6961,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:45:59.931Z",
  "type": "NetworkEvent"
}
```

## TcpConnectionClose

Example: `wget -qO- -6 google.com`

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-12-11T12:31:24.089Z",
    "cloned": false,
    "pid": 47663,
    "tid": 47663,
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
    "filename": "wget",
    "binary_path": "/usr/bin/wget",
    "args": "-qO- -6 google.com"
  },
  "parent": {
    "start_time": "2025-12-04T07:30:11.663Z",
    "cloned": false,
    "pid": 2230022,
    "tid": 2230022,
    "ppid": 72741,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "zsh",
    "binary_path": "/usr/bin/zsh",
    "args": ""
  },
  "network_event": {
    "type": "TcpConnectionClose",
    "saddr": "2a00:1370:81a6:3f56:35f:ba59:506b:7d59",
    "daddr": "2a00:1450:4001:80f::200e",
    "sport": 44538,
    "dport": 80,
    "cookie": 63
  },
  "timestamp": "2025-12-11T12:31:24.942Z"
}
```

Example:
```bash
nc -l 7878
telnet localhost 7878
```

```json
{
  "network_event": {
    "cookie": 49184,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 49856,
    "type": "TcpConnectionClose"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "localhost 7878",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "inetutils-telnet",
    "gid": 0,
    "pid": 6961,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:59.923Z",
    "tid": 6961,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:45:59.932Z",
  "type": "NetworkEvent"
}
```

## TcpConnectionAccept

Example:

```bash
nc -l 7878
telnet localhost 7878
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-12-11T12:31:29.950Z",
    "cloned": false,
    "pid": 47767,
    "tid": 47767,
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
    "filename": "nc.openbsd",
    "binary_path": "/usr/bin/nc.openbsd",
    "args": "-l 7878"
  },
  "parent": {
    "start_time": "2025-12-04T07:30:11.663Z",
    "cloned": false,
    "pid": 2230022,
    "tid": 2230022,
    "ppid": 72741,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "zsh",
    "binary_path": "/usr/bin/zsh",
    "args": ""
  },
  "network_event": {
    "type": "TcpConnectionAccept",
    "saddr": "0.0.0.0",
    "daddr": "0.0.0.0",
    "sport": 7878,
    "dport": 0,
    "cookie": 8283
  },
  "timestamp": "2025-12-11T12:31:34.646Z"
}
```
