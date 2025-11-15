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

Executing `curl -6 google.com` produces:

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-05-31T10:05:51.192Z",
    "pid": 2538344,
    "tid": 2538344,
    "ppid": 9425,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "curl",
    "binary_path": "/usr/bin/curl",
    "args": "-6 google.com",
    "container_id": ""
  },
  "network_event": {
    "type": "TcpConnectionEstablish",
    "saddr": "fe80::d497:36b6:16bf:d97b",
    "daddr": "2a00:1450:4010:c08::8b",
    "sport": 33340,
    "dport": 80,
    "cookie": 4109
  },
  "timestamp": "2025-05-31T10:05:51.282Z"
}
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-05-31T10:06:41.249Z",
    "pid": 2538344,
    "tid": 2538344,
    "ppid": 9425,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "curl",
    "binary_path": "/usr/bin/curl",
    "args": "-6 google.com",
    "container_id": ""
  },
  "network_event": {
    "type": "TcpConnectionClose",
    "saddr": "fe80::d497:36b6:16bf:d97b",
    "daddr": "2a00:1450:4010:c08::8b",
    "sport": 0,
    "dport": 80,
    "cookie": 4109
  },
  "timestamp": "2025-05-31T10:06:41.399Z"
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
    "start_time": "2025-05-31T10:06:46.348Z",
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
    "type": "TcpConnectionEstablish",
    "saddr": "127.0.0.1",
    "daddr": "127.0.0.1",
    "sport": 38570,
    "dport": 7878,
    "cookie": 16387
  },
  "timestamp": "2025-05-31T10:06:46.409Z"
}
```

```json
{
  "type": "NetworkEvent",
  "process": {
    "start_time": "2025-05-31T10:06:46.348Z",
    "pid": 2549020,
    "tid": 2549020,
    "ppid": 9425,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "nc.openbsd",
    "binary_path": "/usr/bin/nc.openbsd",
    "args": "-l 7878",
    "container_id": ""
  },
  "network_event": {
    "type": "TcpConnectionAccept",
    "saddr": "0.0.0.0",
    "daddr": "0.0.0.0",
    "sport": 7878,
    "dport": 0,
    "cookie": 24591
  },
  "timestamp": "2025-05-31T10:06:46.418Z"
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
