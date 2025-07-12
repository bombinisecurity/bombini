## FileMon

Detector for file operations. Each event has process information. Supported hooks:

* `security_file_open` hook  provides info about file owner/permissions + permissions with process accessed the file.
* `path_truncate` hook provides info about path truncated by truncate syscall.
* `path_unlink` provides info about path being deleted.
* `path_chmod` provides info about changing file permissions.

### Required Linux Kernel Version

* `security_file_open`: 5.15 or greater
* `path_truncate`: 6.5 or greater 
* `path_unlink`: 6.5 or greater
* `path_chmod`: 6.5 or greater

### Config

Config represents a dictionary with supported LSM BPF file hooks:

* file_open
* path_truncate
* path_unlink
* path_chmod

For each file hook the following options are supported:

* `disable` disables detection for current hook. False by default.

FileMon detector supports process allow/deny list for event filtering. It is global for all hooks.
The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).

Config example:

```yaml
file_open:
  disable: false
path_truncate:
  disable: true
path_unlink:
  disable: true
path_chmod:
  disable: true
process_filter:
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
    "args": "",
    "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
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
    "args": "bombini.log",
    "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
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
    "args": "/etc/passwd",
    "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
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

Event for `security_path_chmod` (file permissions change):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 1235041,
    "tid": 1235041,
    "ppid": 437558,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "chmod",
    "binary_path": "/usr/bin/chmod",
    "args": "+s ./gdb",
    "cgroup_name": "tmux-spawn-dc94c31c-0fb9-42e5-b878-730cf00753d0.scope"
  },
  "hook": {
    "type": "PathChmod",
    "path": "/home/fedotoff/gdb",
    "i_mode": "?rwsr-sr-x"
  },
  "timestamp": "2025-07-12T19:55:50.771Z"
}
```