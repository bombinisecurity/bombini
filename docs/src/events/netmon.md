# NetMon

NetworkEvent represents a collection of events which
describe ingress/egress TCP connections over ipv4/v6.

## TcpConnectionEstablish

Example: `wget -qO- -6 google.com`

```json

{
  "network_event": {
    "cookie": 36894,
    "daddr": "2a00:1450:4010:c01::64",
    "dport": 80,
    "saddr": "2a00:1370:81a6:3f56:3fd6:26ed:b655:ec7a",
    "sport": 33978,
    "type": "TcpConnectionEstablish"
  },
  "process": {
    "args": "-qO- -6 google.com",
    "auid": 1000,
    "binary_path": "/usr/bin/wget",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "wget",
    "gid": 0,
    "pid": 2274372,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274372,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:33.289Z",
  "type": "NetworkEvent"
}
```

Example:
```bash
nc -l 7878
telnet localhost 7878
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-11-21T21:32:13.849Z",
    "pid": 2290814,
    "tid": 2290814,
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
    "filename": "inetutils-telnet",
    "binary_path": "/usr/bin/inetutils-telnet",
    "args": "localhost 7878"
  },
  "network_event": {
    "type": "TcpConnectionEstablish",
    "saddr": "127.0.0.1",
    "daddr": "127.0.0.1",
    "sport": 56424,
    "dport": 7878,
    "cookie": 45066
  },
  "timestamp": "2025-11-23T14:00:58.013Z"
}
```

## TcpConnectionClose

Example: `wget -qO- -6 google.com`

```json
{
  "network_event": {
    "cookie": 36894,
    "daddr": "2a00:1450:4010:c01::64",
    "dport": 80,
    "saddr": "2a00:1370:81a6:3f56:3fd6:26ed:b655:ec7a",
    "sport": 33978,
    "type": "TcpConnectionClose"
  },
  "process": {
    "args": "-qO- -6 google.com",
    "auid": 1000,
    "binary_path": "/usr/bin/wget",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "wget",
    "gid": 0,
    "pid": 2274372,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274372,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:33.817Z",
  "type": "NetworkEvent"
}
```

Example:
```bash
nc -l 7878
telnet localhost 7878
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-05-31T10:07:06.321Z",
    "pid": 2549606,
    "tid": 2549606,
    "ppid": 1434309,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "inetutils-telnet",
    "binary_path": "/usr/bin/inetutils-telnet",
    "args": "localhost 7878",
    "container_id": ""
  },
  "network_event": {
    "type": "TcpConnectionClose",
    "saddr": "127.0.0.1",
    "daddr": "127.0.0.1",
    "sport": 0,
    "dport": 7878,
    "cookie": 16387
  },
  "timestamp": "2025-05-31T10:07:06.453Z"
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
    "start_time": "2025-11-21T21:32:13.849Z",
    "pid": 2290693,
    "tid": 2290693,
    "ppid": 122033,
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
  "network_event": {
    "type": "TcpConnectionAccept",
    "saddr": "0.0.0.0",
    "daddr": "0.0.0.0",
    "sport": 7878,
    "dport": 0,
    "cookie": 53278
  },
  "timestamp": "2025-11-23T14:00:58.013Z"
}
```
