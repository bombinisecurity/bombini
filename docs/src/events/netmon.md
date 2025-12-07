# NetMon

NetworkEvent represents a collection of events which
describe ingress/egress TCP connections over ipv4/v6.

## TcpConnectionEstablish

Example: `wget -qO- -6 google.com`

```json

{
  "network_event": {
    "cookie": 40966,
    "daddr": "2a00:1450:4001:831::200e",
    "dport": 80,
    "saddr": "2a00:1370:81a6:3f56:d13e:2274:416f:dd83",
    "sport": 57300,
    "type": "TcpConnectionEstablish"
  },
  "process": {
    "args": "-qO- -6 google.com",
    "auid": 1000,
    "binary_path": "/usr/bin/wget",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "wget",
    "gid": 0,
    "pid": 2158658,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:48.911Z",
    "tid": 2158658,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:48.949Z",
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
  "network_event": {
    "cookie": 32785,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 37792,
    "type": "TcpConnectionEstablish"
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
    "pid": 2158596,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:46.063Z",
    "tid": 2158596,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:46.066Z",
  "type": "NetworkEvent"
}
```

## TcpConnectionClose

Example: `wget -qO- -6 google.com`

```json
{
  "network_event": {
    "cookie": 40966,
    "daddr": "2a00:1450:4001:831::200e",
    "dport": 80,
    "saddr": "2a00:1370:81a6:3f56:d13e:2274:416f:dd83",
    "sport": 57300,
    "type": "TcpConnectionClose"
  },
  "process": {
    "args": "-qO- -6 google.com",
    "auid": 1000,
    "binary_path": "/usr/bin/wget",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "wget",
    "gid": 0,
    "pid": 2158658,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:48.911Z",
    "tid": 2158658,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:49.461Z",
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
  "network_event": {
    "cookie": 32785,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 37792,
    "type": "TcpConnectionClose"
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
    "pid": 2158596,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:46.063Z",
    "tid": 2158596,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:46.067Z",
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
    "cloned": false,
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
