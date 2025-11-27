# IOUringMon

IOUring detector tracks SQE submitting using `io_uring_submit_req` tracepoint.

Inspired by:

1. [curing example](https://github.com/armosec/curing) and [post](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/).
2. [RingReaper example](https://github.com/MatheuZSecurity/RingReaper) and [post](https://matheuzsecurity.github.io/hacking/evading-linux-edrs-with-io-uring/).

## Required Linux Kernel Version

6.8 or greater

## Config Description

IOUringMon detector supports [process filtering](filtering.md/#process-filter).

Config example:

```yaml
process_fiter:
  uid:
    - 0
  euid:
    - 0
  binary:
    name:
      - nslookup
```