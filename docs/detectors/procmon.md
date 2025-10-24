## Procmon

Procmon is the main detector that collects information about process being spawend and detached.
Information about living process is stored shared map and other detectors are using it.

### Required Linux Kernel Version

5.15 or greater

### Config

Procmon detector supports allow/deny list for events filtereing. Let's look at the config example.

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
Filter list section is start by defining `process_filter`.
events that DO satisfy the following conditions will be send to user space.
`deny_list` is set false by default. It indicates that filter is acts like deny lists:
events that do NOT satisfiy the following conditions will be
send to user space. Conditions: `uid`, `eud`, `auid`, `binary` are combined with logical "AND".
The values in these fields are represented as arrays, and are combined with
logical "OR". Fields `name`, `prefix`, `path` in the `binary` section are combined with logical "OR".

It is possible to enable IMA hashes of executed binary in process information.
To enable put this to config (false by default):

```yaml
ima_hash: true
```

### Privilege escalation detection hooks

Procmon helps to monitor privilege escalation during process execution. It uses LSM hooks for this:

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

Cred filter can be applied to these hooks:

* security_task_fix_setuid
* security_capset
* security_create_user_ns

`cred_filter` supports filtering by EUID and effective capabilies. They are combined with OR logic operator.
`cap_filter` supports `deny_list` that acts like NOT operator. `cap_filter` supports `ANY` key word  that equal
the check if any capability is set (not equal 0).

### Event

```json
{
    "type": "ProcessExec",
    "process": {
      "pid": 746925,
      "tid": 746925,
      "ppid": 462192,
      "uid": 1000,
      "euid": 1000,
      "auid": 1000,
      "cap_inheritable": 0,
      "cap_permitted": 0,
      "cap_effective": 0,
      "secureexec": "",
      "filename": "git",
      "binary_path": "/usr/bin/git",
      "args": "rev-parse --quiet --verify HEAD",
      "container_id": ""
    },
    "timestamp": "2025-05-31T09:04:45.896Z"
  }
```
```json
  {
    "type": "ProcessExit",
    "process": {
      "pid": 746925,
      "tid": 746925,
      "ppid": 462192,
      "uid": 1000,
      "euid": 1000,
      "auid": 1000,
      "cap_inheritable": 0,
      "cap_permitted": 0,
      "cap_effective": 0,
      "secureexec": "",
      "filename": "git",
      "binary_path": "/usr/bin/git",
      "args": "rev-parse --quiet --verify HEAD",
      "container_id": ""
    },
    "timestamp": "2025-05-31T09:04:45.909Z"
  }
```

Event with IMA hash of executed binary:

```json
{
  "type": "ProcessExec",
  "process": {
    "pid": 518616,
    "tid": 518616,
    "ppid": 3573,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "cat",
    "binary_path": "/usr/bin/cat",
    "args": "/etc/passwd",
    "container_id": "",
    "binary_ima_hash": "sha256:dda0961715677dff3cd560e1933379c0eca73c0b6e19fef2737492ebc1de1700"
  },
  "timestamp": "2025-09-18T16:55:41.559Z"
}
```
Fileless execution:

```json
{
  "type": "ProcessExec",
  "process": {
    "pid": 133303,
    "tid": 133303,
    "ppid": 131958,
    "uid": 0,
    "euid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "FILELESS_EXEC",
    "filename": "memfd:fileless-exec-test",
    "binary_path": "/memfd:fileless-exec-test (deleted)",
    "args": "fileless-exec-test",
    "container_id": ""
  },
  "timestamp": "2025-08-31T15:26:52.044Z"
}
```


Privilege escalation events:

```json

  "type": "ProcessSetUid",
  "process": {
    "pid": 1630276,
    "tid": 1630276,
    "ppid": 1630275,
    "uid": 1000,
    "euid": 0,
    "auid": 0,
    "cap_inheritable": 0,
    "cap_permitted": 2199023255551,
    "cap_effective": 2199023255551,
    "secureexec": "",
    "filename": "sudo",
    "binary_path": "/usr/bin/sudo",
    "args": "-u nobody true",
    "container_id": ""
  },
  "euid": 65534,
  "uid": 65534,
  "fsuid": 65534,
  "flags": "LSM_SETID_RES",
  "timestamp": "2025-07-31T07:40:10.920Z"
}
```

```json
{
  "type": "ProcessCapset",
  "process": {
    "pid": 2223566,
    "tid": 2223566,
    "ppid": 2223565,
    "uid": 0,
    "euid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "capsh",
    "binary_path": "/usr/sbin/capsh",
    "args": "--caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "container_id": ""
  },
  "inheritable": "",
  "permitted": "CAP_NET_RAW | CAP_SYS_ADMIN",
  "effective": "CAP_NET_RAW | CAP_SYS_ADMIN",
  "timestamp": "2025-07-31T20:19:24.606Z"
}
```

```json
{
  "type": "ProcessPrctl",
  "process": {
    "pid": 32905,
    "tid": 32905,
    "ppid": 11551,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "capsh",
    "binary_path": "/usr/sbin/capsh",
    "args": "--keep=1 -- -c echo KEEPCAPS enabled",
    "container_id": ""
  },
  "cmd": {
    "PrSetKeepCaps": 1
  },
  "timestamp": "2025-08-02T13:38:03.693Z"
}
```
```json
{
  "type": "ProcessCreateUserNs",
  "process": {
    "pid": 619892,
    "tid": 619892,
    "ppid": 9790,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "unshare",
    "binary_path": "/usr/bin/unshare",
    "args": "-U",
    "container_id": ""
  },
  "timestamp": "2025-08-06T20:07:26.954Z"
}
```

```json
{
  "type": "ProcessPtraceAccessCheck",
  "process": {
    "pid": 819092,
    "tid": 819092,
    "ppid": 716378,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "gdb",
    "binary_path": "/usr/bin/gdb",
    "args": "attach -p 818867",
    "container_id": ""
  },
  "child": {
    "pid": 818867,
    "tid": 818867,
    "ppid": 9790,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "vim.basic",
    "binary_path": "/usr/bin/vim.basic",
    "args": "",
    "container_id": ""
  },
  "mode": "PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS",
  "timestamp": "2025-08-09T15:15:55.916Z"
}
```
