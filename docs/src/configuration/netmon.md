# NetMon

NetMon detector provides information about ingress/egress TCP connections
based on IPv4/IPv6. It also provides information about socket events.

Hooks:

- `tcp_v4_connect`: collect egress TCP IPv4 connection requests
- `tcp_v6_connect`: collect egress TCP IPv6 connection requests
- `tcp_close`: collect connection close events
- `inet_csk_accept`: collect TCP v4/v6 ingress connections
- `socket_create`: collect socket creation events
- `socket_create`: collect socket connect events

## Required Linux Kernel Version

6.2 or greater

## Config Description

Config represents a dictionary with supported hooks for ingress/egress tcp connections and socket events:

* `ingress`
* `egress`
* `socket_create`
* `socket_connect`

## Event Filtering

All hooks support scope and event filtering.
Hooks for socket events support sandbox mode. Hooks for tcp connections does not.

### Tcp Connections

NetMon supports attributes filtering for ingress/egress tcp connection events.

* `ipv4_dst` - destination IPv4 address of ingress/egress tcp connection
* `ipv4_src` - source IPv4 address of ingress/egress tcp connection
* `ipv6_dst` - destination IPv6 address of ingress/egress tcp connection
* `ipv6_src` - source IPv6 address of ingress/egress tcp connection
* `port_src` - source port of ingress/egress tcp connection
* `port_dst` - destination port of ingress/egress tcp connection

**Examples**

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

```yaml
egress:
  enabled: true
  rules:
  - rule: tcp-connections-to-api-server
    event: ipv4_dst == "10.96.0.1" AND port_dst == 443
```

### Socket Creation

NetMon supports attributes filtering for socket creation events.

* `family` - socket address family (AF_INET, AF_INET6, AF_UNIX, ...).
* `type` - socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, ...).
* `flags` - socket flags. This attribute is treated as mask and can have multiple values at a runtime (e.g., SOCK_NONBLOCK and SOCK_CLOEXEC simultaneously).
* `protocol` - socket protocol.

**Examples**

```yaml
socket_create:
  enabled: true
  rules:
  - rule: socket-creation
    event: (family == "AF_INET6" OR family == "AF_INET")AND type == "SOCK_STREAM"
```

For more information about socket attributes see [man](https://man7.org/linux/man-pages/man2/socket.2.html).

### Socket Connect

NetMon supports attributes filtering for socket connect events.

* `ipv4_dst` - destination IPv4 address of egress connection
* `ipv6_dst` - destination IPv6 address of egress connection
* `port_dst` - destination port of egress connection

**Examples**

```yaml
socket_connect:
  enabled: true
  rules:
  - rule: socket-connect
    event: ipv4_dst == "10.96.0.1" AND port_dst == 443 OR ipv6_dst == "2000::/3"
```

For more information about socket attributes see [man](https://man7.org/linux/man-pages/man2/connect.2.html).
We only support 2 socket address families: AF_INET and AF_INET6. This hook can be used for NetMon connections enforcement.
