## FileMon

Detector for file operations. Each event has process information. Supported hooks:

* `security_file_open` hook  provides info about file owner/permissions + permissions with process accessed the file.
* `path_truncate` hook provides info about path truncated by truncate syscall.
* `path_unlink` provides info about path being deleted.

### Config

Config represents a dictionary with supported LSM BPF file hooks:

* file-open
* path-truncate
* path-unlink

For each file hook the following options are supported:

* `disable` disables detection for current hook. False by default.
* `expose-events` sends events to user-mode. True by default.

FileMon detector supports process allow/deny list for event filtering. It is global for all hooks.
The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).

Config example:

```yaml
file-open:
  expose-events: true
path-truncate:
  disable: true
path-unlink:
  expose-events: true
process_allow_list:
  binary:
    name:
      - tail
    path:
      - /usr/bin/cat
```

### Event

Event for `security_path_truncate` (truncating file):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 742873,
    "tid": 742873,
    "ppid": 462192,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "tr",
    "binary_path": "/home/fedotoff/tr",
    "args": ""
  },
  "hook": {
    "type": "PathTruncate",
    "path": "/home/fedotoff/bombini/bombini.log"
  },
  "timestamp": "2025-05-31T10:01:41.741Z"
}
```

Event for `security_path_unlink` (deleting file):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 743301,
    "tid": 743301,
    "ppid": 462192,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "rm",
    "binary_path": "/usr/bin/rm",
    "args": "bombini.log"
  },
  "hook": {
    "type": "PathUnlink",
    "path": "/home/fedotoff/bombini/bombini.log"
  },
  "timestamp": "2025-05-31T10:02:15.812Z"
}
```

Event for `security_file_open` (opening file):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 744458,
    "tid": 744458,
    "ppid": 462192,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "cat",
    "binary_path": "/usr/bin/cat",
    "args": "/etc/passwd"
  },
  "hook": {
    "type": "FileOpen",
    "path": "/etc/passwd",
    "access_mode": "O_RDONLY",
    "creation_flags": "O_LARGEFILE",
    "uid": 0,
    "gid": 0,
    "i_mode": "-rw-r--r--"
  },
  "timestamp": "2025-05-31T10:02:45.887Z"
}
```
