# ProcMon

ProcMon is the main detector that collects information about process being spawned and detached.
Information about living process is stored shared map and other detectors are using it. Every other
detector needs ProcMon that monitors process execs and exits. So, this detector can not be disabled.

## Required Linux Kernel Version

6.2 or greater

## Config Description

ProcMon supports [process filtering](filtering.md/#process-filter).

Config example:

```yaml
expose_events: true
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

`expose_events` sends events to user-mode. False by default.
If you want to send events you should set expose_events to true with filters or without.

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

[Cred filter](filtering.md/#cred--filter) can be applied to these hooks:

* security_task_fix_setuid
* security_capset
* security_create_user_ns