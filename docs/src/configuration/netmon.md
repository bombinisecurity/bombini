# NetMon

NetMon detector provides information about ingress/egress TCP connections
based on IPv4/IPv6

Hooks:

- `tcp_v4_connect`: collect egress TCP IPv4 connection requests
- `tcp_v6_connect`: collect egress TCP IPv6 connection requests
- `tcp_close`: collect connection close events
- `inet_csk_accept`: collect TCP v4/v6 ingress connections

## Required Linux Kernel Version

6.2 or greater

## Config Description

First you need to enable monitoring for ingress/egress tcp connections or both:

```yaml
ingress:
  enabled: true
egress:
  enabled: true
```

NetMon supports [filtering by IP](filtering.md/#ip-filter). You can have separate filters for ingress/egress traffic.

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

The example above shows NetMon config that can detect outgoing connections from cluster network.

NetMon detector supports [process filtering](filtering.md/#process-filter).