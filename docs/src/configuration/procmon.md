# ProcMon

ProcMon is the main detector that collects information about process being spawned and detached.
Information about living process is stored in shared eBPF map and in Process cache in user space.
Every other detector needs ProcMon that monitors process execs and exits. This detector cannot be disabled.

## Required Linux Kernel Version

6.2 or greater

## Config Description

It is possible to enable IMA hashes of executed binary in process information.
To enable put this to config (false by default):

```yaml
ima_hash: true
```

It is possible to set garbage collection period in seconds for `PROCMON_PROC_MAP` (process info in eBPF).
Default value is 30 sec.

```yaml
gc_period: 30
```

## Process Hooks

ProcMon helps to monitor privilege escalation during process execution. It uses LSM hooks for this:

* security_task_fix_setuid (config name: setuid)
* security_task_fix_setgid (config name: setgid)
* security_capset (config name: capset)
* security_task_prctl (config name: prctl)
* security_create_user_ns (config name: create_user_ns)
* security_ptrace_access_check (config name: ptrace_access_check)

To enable hook:

```yaml
<hook>:
  enabled: true
```

## Event Filtering

All hooks support scope filtering.

The following list of hooks support event filtering by rules:

* security_task_fix_setuid
* security_task_fix_setgid
* security_capset
* security_create_user_ns

### security_task_fix_setuid

`setuid` supports the following filtering attributes:

* `uid` - new uid
* `euid` - new euid

**Example**

```yaml
setuid:
  enabled: true
  rules:
  - rule: UidTestRule
    event: uid == 1000 AND euid == 0
```

### security_task_fix_setgid

`setgid` supports the following filtering attributes:

* `gid` - new gid
* `egid` - new egid

**Example**

```yaml
setgid:
  enabled: true
  rules:
  - rule: GidTestRule
    event: gid == 1000 AND egid == 0
```

### security_capset

`capset` supports the following filtering attributes:

* `ecaps` - new effective capabilities
* `pcaps` - new permitted capabilities

List of capabilities can be found in [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).
we support a placeholder `ANY_CAPS` that matches all capabilities. Expression `ecaps in ["ANY_CAPS"]` or `ecaps == "ANY_CAPS"` checks if any capability is set.

**Example**

```yaml
setcaps:
  enabled: true
  rules:
  - rule: CapsTestRule
    event: ecaps == "CAP_SYS_ADMIN"
```

### security_create_user_ns

`create_user_ns` supports the following filtering attributes:

* `ecaps` - effective capabilities
* `euid` - effective uid

**Example**

```yaml
create_user_ns:
  enabled: true
  rules:
  - rule: UnprivNsTestRule
    event: NOT ecaps == "CAP_SYS_ADMIN"
```
