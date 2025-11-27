# Filtering

In this chapter various filters for event are described.
This filters are applied in eBPF side.

## Process Filter

Filter is defined by `process_filter` keyword.
Events that **DO** satisfy the following conditions will be send to userspace.
`deny_list` is set false by default. It inverts the defined condition:
events that **DO NOT** satisfy the following conditions will be
send to userspace.

Conditions: `uid`, `eud`, `auid`, `binary` are combined with logical "AND".
The values in each section are represented as arrays, and are combined with
logical "OR". `binary` represents a `path_filter`Fields `name`, `prefix`, `path` in the `binary` section are combined with logical "OR".

Process filter is global for detector and applied to all events in this detector.
Process filter combined with AND operation to other filters.

Filter explanation with boolean logic:

```
NOT process_filter // deny_list logic
uid && euid && auid && binary // all filter logic
uid && euid && auid && (name || prefix || path)
```

Example:
```yaml
process_filter:
  deny_list: false
  uid:
    - 0
  euid:
    - 0
  auid:
    - 1000
  binary:
    name:
      - tail
      - curl
    prefix:
      - /usr/local/bin/
    path:
      - /usr/bin/uname
```

## Path Filter

Filter represents an allow list of paths using name, prefix, or full path.
If path has corresponding name, prefix or equals the provided full path event will be send.

Filter explanation with boolean logic:

```
name || prefix || path // all items united with OR operator
```

Example:

```yaml
  path_filter:
    name:
      - .history
      - .bash_history
    prefix:
      - /boot
    path:
      - /etc/passwd
```

## IP Filter

IP filters can act as allow list or deny list and they are united with OR operator.
In this filters there are source ip lists, and destination ip lists. Filters for ipv4 and ipv6 are separate.

Filter explanation with boolean logic:

```
ipv4_filter || ipv6_filter // ipv4/ipv6  filter united with OR 
NOT ipv4_filter // ipv4 filter deny_list
NOT ipv6_filter // ipv6 filter deny_list
dest_ip || src_ip // dest and src lists are united with OR
```

Example:

```yaml
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

## Cred  Filter

`cred_filter` supports filtering by euid and effective capabilities. They are combined with OR logic operator.
`cap_filter` supports `deny_list` that acts like NOT operator. `cap_filter` supports `ANY` key word  that equal
the check if any capability is set (not equal 0).

Filter explanation with boolean logic:
```
cap_filter || uid_filter // filters united with OR condition
NOT cap_filter // deny_list
euid || effective // cap_filter has only effective caps, uid_filter only euid
```

Example:

```yaml
cred_filter:
uid_filter:
    euid:
    - 0
cap_filter:
    effective:
    - "CAP_SYS_ADMIN"
    deny_list: true
```