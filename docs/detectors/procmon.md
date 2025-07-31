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

### Privilege escalation detection hooks

Procmon helps to monitor privilege escalation during process execution. It uses LSM hooks for this:

* security_task_fix_setuid

To enable `setuid` events put this to config:

```yaml
setuid:
  disable: false
```

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
      "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
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
      "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
    },
    "timestamp": "2025-05-31T09:04:45.909Z"
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
    "cgroup_name": ""
  },
  "euid": 65534,
  "uid": 65534,
  "fsuid": 65534,
  "flags": "LSM_SETID_RES",
  "timestamp": "2025-07-31T07:40:10.920Z"
}
```