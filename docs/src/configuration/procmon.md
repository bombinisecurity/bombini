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
* security_bprm_check (config name: bprm_check)

Also there is a tracepoint hook only for sandbox mode: sched_process_exec. It allows to block execs by sending SIGKILL to the process.

To enable hook:

```yaml
<hook>:
  enabled: true
```

## Event Filtering

All hooks support scope filtering. In addition to the `binary_*` attributes, ProcMon scope
filtering supports matching the direct parent process binary via the `parent_binary_path`,
`parent_binary_name` and `parent_binary_prefix` attributes (see [Rules](./rules.md)).

The following list of hooks support event filtering by rules and sandbox mode:

* security_task_fix_setuid
* security_task_fix_setgid
* security_capset
* security_create_user_ns
* security_bprm_check
* sched_process_exec

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

### security_bprm_check

`bprm_check` supports the following filtering attributes:

* `path` - absolute path of executed binary via exec
* `name` - name of executed binary via exec
* `path_prefix` - absolute path prefix of executed binary via exec
* `euid` - euid of executed binary via exec
* `egid` - egid of executed binary via exec
* `ecaps` - effective capabilities of executed binary via exec

**Example**

```yaml
bprm_check:
  enabled: true
  rules:
  - rule: TestBprmCheck
    event: path_prefix == "/tmp" AND name == "ls"
```

### sched_process_exec

`sched_process_exec` supports the following filtering attributes:

* `arg0-arg31` - arguments of executed binary. The index at the end of the argument allows to distinguish between arguments. It is NOT the index of the argument in `argv` array.

This hook is only available in sandbox mode, which is always enabled. It is used to block execs by sending SIGKILL to the process.

**Example**

```yaml
sched_process_exec:
  enabled: true
  rules:
  - rule: ExecveSandboxTestRule
    scope: binary_name == "rm"
    event: arg0 in ["-r", "-rf"] AND arg1 in ["/etc/passwd"]
```

In this example, we block all execs of `rm` binary if one of the arguments is `-r` or `-rf` and another is `/etc/passwd`.
