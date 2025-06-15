## Procmon

Procmon is the main detector that collects information about process being spawend and detached.
Information about living process is stored shared map and other detectors are using it. Procmon
can produce events about when the process starts and ends.

### Config

Procmon detector supports allow/deny list for events filtereing. Let's look at the config example.

```yaml
expose-events: true
process_allow_list:
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

`expose-events` sends events to user-mode. False by default.
If you want to send events you should set expose-events to true no matter using filters or not.
Filter list section is start by defining allow list `process_allow_list`:
events that DO satisfy the following conditions will be send to user space,
or deny list `process_deny_list`: events that do NOT satisfiy the following conditions will be
send to user space. Next level of hierarchy provide the types of conditions: `uid`, `eud`, `auid`, `binary`.
This types of conditions combined with logical "AND". Values are represented as arrays, are combined with
logical "OR". `name`, `prefix`, `path` in the `binary` section are combined with logical "OR" too.


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
      "args": "rev-parse --quiet --verify HEAD"
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
      "args": "rev-parse --quiet --verify HEAD"
    },
    "timestamp": "2025-05-31T09:04:45.909Z"
  }
```
