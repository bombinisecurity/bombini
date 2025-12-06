# ProcMon

ProcMon is the main detector that collects information about process being spawned and detached.
Information about living process is stored shared map and other detectors are using it. Every other
detector needs ProcMon that monitors process execs and exits. So, this detector can not be disabled.

## Required Linux Kernel Version

6.2 or greater

## Config Description

It is possible to enable IMA hashes of executed binary in process information.
To enable put this to config (false by default):

```yaml
ima_hash: true
```

## Process Hooks

ProcMon helps to monitor privilege escalation during process execution. It uses LSM hooks for this:

* security_task_fix_setuid
* security_capset
* security_task_prctl
* security_create_user_ns

To enable `setuid` events put this to config:

```yaml
setuid:
  enabled: true
```

Enabling `capset` events:

```yaml
capset:
  enabled: true
```

Enabling `prctl` events:

```yaml
prctl:
  enabled: true
```

Enabling `create_user_ns` events:

```yaml
create_user_ns:
  enabled: true
```

Enabling `ptrace_access_check` events:

```yaml
ptrace_access_check:
  enabled: true
```

ProcMon supports [process filtering](filtering.md/#process-filter).

[Cred filter](filtering.md/#cred--filter) can be applied to these hooks:

* security_task_fix_setuid
* security_capset
* security_create_user_ns

Config example:

```yaml
setuid:
  enabled: true
  cred_filter:
    uid_filter:
      euid:
      - 0
capset:
  enabled: true
  cred_filter:
    cap_filter:
      effective:
      - "ANY"
create_user_ns:
  enabled: true
  cred_filter:
    cap_filter:
      effective:
      - "CAP_SYS_ADMIN"
      deny_list: true

process_filter:
  uid:
    - 0
  euid:
    - 0
  auid:
    - 1000
  binary:
    prefix:
      - /usr/bin/
      - /usr/sbin/
```