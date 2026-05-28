# NetMon

NetworkEvent represents a collection of events which
describe ingress/egress TCP connections over ipv4/v6.

## TcpConnectionEstablish

Example:
```bash
nc -l 7878
telnet -6 localhost 7878
```

```json
{
  "network_event": {
    "cookie": 32771,
    "daddr": "::1",
    "dport": 7879,
    "saddr": "::1",
    "sport": 59986,
    "type": "TcpConnectionEstablish"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/netmon-8844df73ce6a95b2",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "filename": "netmon-8844df73ce6a95b2",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84537,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:19.288Z",
    "tid": 84537,
    "uid": 0
  },
  "process": {
    "args": "-6 localhost 7879",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjA6ODY5NTA2ODg5NjExMjM4",
    "filename": "inetutils-telnet",
    "gid": 0,
    "parent_exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "pid": 84660,
    "ppid": 84537,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:31.908Z",
    "tid": 84660,
    "uid": 0
  },
  "rule": "NetMonIpv6Test",
  "timestamp": "2026-04-30T11:43:31.910Z",
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
    "cookie": 4099,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 53484,
    "type": "TcpConnectionEstablish"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/netmon-8844df73ce6a95b2",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "filename": "netmon-8844df73ce6a95b2",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84537,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:19.288Z",
    "tid": 84537,
    "uid": 0
  },
  "process": {
    "args": "localhost 7878",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2MDY6ODY5NTAwMjc2MTA1NTEz",
    "filename": "inetutils-telnet",
    "gid": 0,
    "parent_exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "pid": 84606,
    "ppid": 84537,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:25.294Z",
    "tid": 84606,
    "uid": 0
  },
  "rule": "NetMonIpv4Test",
  "timestamp": "2026-04-30T11:43:25.295Z",
  "type": "NetworkEvent"
}
```

## TcpConnectionClose

Example:
```bash
nc -l 7878
telnet -6 localhost 7878
```

```json
{
  "network_event": {
    "cookie": 32771,
    "daddr": "::1",
    "dport": 7879,
    "saddr": "::1",
    "sport": 59986,
    "type": "TcpConnectionClose"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/netmon-8844df73ce6a95b2",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "filename": "netmon-8844df73ce6a95b2",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84537,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:19.288Z",
    "tid": 84537,
    "uid": 0
  },
  "process": {
    "args": "-6 localhost 7879",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjA6ODY5NTA2ODg5NjExMjM4",
    "filename": "inetutils-telnet",
    "gid": 0,
    "parent_exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "pid": 84660,
    "ppid": 84537,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:31.908Z",
    "tid": 84660,
    "uid": 0
  },
  "timestamp": "2026-04-30T11:43:31.910Z",
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
    "cookie": 4099,
    "daddr": "127.0.0.1",
    "dport": 7878,
    "saddr": "127.0.0.1",
    "sport": 53484,
    "type": "TcpConnectionClose"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/netmon-8844df73ce6a95b2",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "filename": "netmon-8844df73ce6a95b2",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84537,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:19.288Z",
    "tid": 84537,
    "uid": 0
  },
  "process": {
    "args": "localhost 7878",
    "auid": 1000,
    "binary_path": "/usr/bin/inetutils-telnet",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2MDY6ODY5NTAwMjc2MTA1NTEz",
    "filename": "inetutils-telnet",
    "gid": 0,
    "parent_exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "pid": 84606,
    "ppid": 84537,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:25.294Z",
    "tid": 84606,
    "uid": 0
  },
  "timestamp": "2026-04-30T11:43:25.296Z",
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
    "exec_id": "ODQ1ODY6ODY5NDk4Nzc1Njg0MTEx",
    "parent_exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
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
    "exec_id": "ODQ1Mzc6ODY5NDk0MjcwMDAwMDAw",
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
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

## SocketCreate

Example:

```bash
nc -l 7878
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2026-05-28T15:45:13.131Z",
    "cloned": false,
    "pid": 3445,
    "tid": 3445,
    "ppid": 1778,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "nc.openbsd",
    "binary_path": "/usr/bin/nc.openbsd",
    "args": "-l 7878",
    "exec_id": "MzQ0NToxMTUwMDI0MjcxNTAxNA",
    "parent_exec_id": "MTc3ODoxMjc2MDAwMDAwMA"
  },
  "parent": {
    "start_time": "2026-05-28T12:33:45.648Z",
    "cloned": false,
    "pid": 1778,
    "tid": 1778,
    "ppid": 1700,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": "--login",
    "exec_id": "MTc3ODoxMjc2MDAwMDAwMA",
    "parent_exec_id": "MTcwMDo5NjEwMDAwMDAw"
  },
  "blocked": false,
  "network_event": {
    "type": "SocketCreate",
    "family": "AF_INET",
    "sock_type": "SOCK_STREAM",
    "flags": "",
    "protocol": 6
  },
  "timestamp": "2026-05-28T15:45:13.133Z"
}
```

## SocketConnect

Example:

```bash
nc -l 7871
telnet localhost 7871
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2026-05-31T13:56:01.177Z",
    "cloned": false,
    "pid": 17649,
    "tid": 17649,
    "ppid": 1830,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "inetutils-telnet",
    "binary_path": "/usr/bin/inetutils-telnet",
    "args": "-4 localhost 7871",
    "exec_id": "MTc2NDk6ODg1Njg1ODQ4OTg0MQ",
    "parent_exec_id": "MTgzMDoyMTUxMDAwMDAwMA"
  },
  "parent": {
    "start_time": "2026-05-31T11:28:45.829Z",
    "cloned": false,
    "pid": 1830,
    "tid": 1830,
    "ppid": 1753,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": "--login",
    "exec_id": "MTgzMDoyMTUxMDAwMDAwMA",
    "parent_exec_id": "MTc1MzoxNTIyMDAwMDAwMA"
  },
  "blocked": false,
  "network_event": {
    "type": "SocketConnect",
    "family": "AF_INET",
    "sock_type": "SOCK_STREAM",
    "protocol": 6,
    "daddr": "127.0.0.1",
    "dport": 7871
  },
  "timestamp": "2026-05-31T13:56:01.181Z",
  "rule": "SocketConnecttestRule"
}
```
