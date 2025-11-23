## Netmon

Netmon detector provides information about ingress/egress TCP connections
based on IPv4/IPv6

Hooks:

- `tcp_v4_connect`: collect egnress TCP IPv4 connection requests
- `tcp_v6_connect`: collect egnress TCP IPv6 connection requests
- `tcp_close`: collect connection close events
- `inet_csk_accept`: collect TCP v4/v6 ingress connections

### Required Linux Kernel Version

6.2 or greater

### Config

First you need to enable monitoring for ingress/egress tcp connections or both:

```yaml
ingress:
  enabled: true
egress:
  enabled: true
```

Netmon supports filtering by IP. You can have separate filters for ingress/egress traffic.
For each filter there are ipv4 and ipv6 lists. This ip filters can act as allow list or deny list
and they are united with OR operator. In this filters there are source ip lists, and destination ip lists.

```yaml
egress:
  enabled: true
  ipv4_filter:
    deny_list: true
    dst_ip:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.1
      - 0.0.0.0
  ipv6_filter:
    dst_ip:
      - 2000::/3
```

The example above shows Netmon config that can detect outgoing connections from cluster network.

NetMon detector supports process allow/deny list for event filtering:

```yaml
process_filter:
  binary:
    name:
      - curl
```

The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).
Allow/deny process filter list is common for ingress/egress connections.

### Event

Executing `wget -qO- -6 google.com` produces:

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
Executing

```bash
nc -l 7878
telnet localhost 7878
```

produce the following events:

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
