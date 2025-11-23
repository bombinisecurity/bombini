## Procmon

Procmon is the main detector that collects information about process being spawend and detached.
Information about living process is stored shared map and other detectors are using it.

### Required Linux Kernel Version

6.2 or greater

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
  "process": {
    "args": "--follow-symlinks s/// /dev/null",
    "auid": 1000,
    "binary_path": "/usr/bin/tmux",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "egid": 1000,
    "euid": 1000,
    "filename": "sed",
    "gid": 1000,
    "pid": 2274635,
    "ppid": 2274634,
    "secureexec": "",
    "start_time": "2025-11-23T13:47:43.767Z",
    "tid": 2274635,
    "uid": 1000
  },
  "timestamp": "2025-11-23T13:47:43.767Z",
  "type": "ProcessExec"
}
```
```json
{
  "process": {
    "args": "--follow-symlinks s/// /dev/null",
    "auid": 1000,
    "binary_path": "/usr/bin/tmux",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "egid": 1000,
    "euid": 1000,
    "filename": "sed",
    "gid": 1000,
    "pid": 2274635,
    "ppid": 2274634,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274635,
    "uid": 1000
  },
  "timestamp": "2025-11-23T13:47:43.769Z",
  "type": "ProcessExit"
}
```

Event with IMA hash of executed binary:

```json
{
  "process": {
    "args": "-lah",
    "auid": 1000,
    "binary_ima_hash": "sha256:0148f5ab3062a905281d8deb9645363da5131011c9e7b6dcaa38b504e41b68ea",
    "binary_path": "/usr/bin/ls",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "ls",
    "gid": 0,
    "pid": 2274735,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-23T13:47:48.187Z",
    "tid": 2274735,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:48.187Z",
  "type": "ProcessExec"
}
```
Fileless execution:

```json
{
  "process": {
    "args": "fileless-exec-test",
    "auid": 1000,
    "binary_path": "/memfd:fileless-exec-test (deleted)",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "memfd:fileless-exec-test",
    "gid": 0,
    "pid": 2274676,
    "ppid": 2273865,
    "secureexec": "FILELESS_EXEC",
    "start_time": "2025-11-23T13:47:45.526Z",
    "tid": 2274676,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:45.526Z",
  "type": "ProcessExec"
}
```


Privilege escalation events:

```json
{
  "process": {
    "args": "-u nobody true",
    "auid": 1000,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "sudo",
    "gid": 0,
    "pid": 2274927,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274927,
    "uid": 0
  },
  "process_event": {
    "euid": 0,
    "flags": "LSM_SETID_RES",
    "fsuid": 0,
    "type": "Setuid",
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:56.435Z",
  "type": "ProcessEvent"
}
```

```json
{
  "process": {
    "args": "--caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "capsh",
    "gid": 0,
    "pid": 2274860,
    "ppid": 2274859,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274860,
    "uid": 0
  },
  "process_event": {
    "effective": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "inheritable": "",
    "permitted": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "type": "Setcaps"
  },
  "timestamp": "2025-11-23T13:47:53.639Z",
  "type": "ProcessEvent"
}
```

```json
{
  "process": {
    "args": "--keep=1 -- -c echo KEEPCAPS enabled",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "capsh",
    "gid": 0,
    "pid": 2274793,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274793,
    "uid": 0
  },
  "process_event": {
    "cmd": {
      "PrSetKeepCaps": 1
    },
    "type": "Prctl"
  },
  "timestamp": "2025-11-23T13:47:50.743Z",
  "type": "ProcessEvent"
}
```
```json
{
  "process": {
    "args": "-U",
    "auid": 1000,
    "binary_path": "/usr/bin/unshare",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "unshare",
    "gid": 0,
    "pid": 2274557,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274557,
    "uid": 0
  },
  "process_event": {
    "type": "CreateUserNs"
  },
  "timestamp": "2025-11-23T13:47:40.589Z",
  "type": "ProcessEvent"
}
```

```json
{
  "type": "ProcessEvent",
  "process": {
    "start_time": "2025-10-27T06:37:34.713Z",
    "pid": 4130822,
    "tid": 4130822,
    "ppid": 3715631,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "gdb",
    "binary_path": "/usr/bin/gdb",
    "args": "attach -p 4130361"
  },
  "process_event": {
    "type": "PtraceAccessCheck",
    "child": {
      "start_time": "2025-10-27T06:37:34.713Z",
      "pid": 4130361,
      "tid": 4130361,
      "ppid": 4130287,
      "uid": 1000,
      "euid": 1000,
      "gid": 1000,
      "egid": 1000,
      "auid": 1000,
      "cap_inheritable": "",
      "cap_permitted": "",
      "cap_effective": "",
      "secureexec": "",
      "filename": "vim.basic",
      "binary_path": "/usr/bin/vim.basic",
      "args": ""
    },
    "mode": "PTRACE_MODE_ATTACH | PTRACE_MODE_FSCRED"
  },
  "timestamp": "2025-11-02T15:00:01.211Z"
}
```
