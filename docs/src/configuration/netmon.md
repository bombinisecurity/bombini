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

## Event Filtering

NetMon supports attributes filtering for ingress/egress tcp connection events.

* `ipv4_dst` - destination IPv4 address of ingress/egress tcp connection
* `ipv4_src` - source IPv4 address of ingress/egress tcp connection
* `ipv6_dst` - destination IPv6 address of ingress/egress tcp connection
* `ipv6_src` - source IPv6 address of ingress/egress tcp connection

**Example**

```yaml
egress:
  enabled: true
  rules:
  - rule: tcp-connections-out-of-cluster
    event: >
      NOT ipv4_dst in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.1",
        "0.0.0.0"
      ] OR ipv6_dst == "2000::/3"
```