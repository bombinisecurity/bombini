## FileMon

Detector for file operations. Each event has process information. Supported LSM hooks:

* `file_open` hook  provides info about file owner/permissions + permissions with process accessed the file.
* `mmap_file` hook proivdes info about mmaped file: path, protetcion flags.
* `path_truncate` hook provides info about path truncated by truncate syscall.
* `path_unlink` provides info about path being deleted.
* `path_chmod` provides info about changing file permissions.
* `path_chown` provides info about changing file owner.
* `sb_mount` provides info about mounted devices.

### Required Linux Kernel Version

* `file_open`: 5.15 or greater
* `mmap_file`: 5.15 or greater
* `path_truncate`: 6.5 or greater 
* `path_unlink`: 6.5 or greater
* `path_chmod`: 6.5 or greater
* `path_chown`: 6.5 or greater
* `sb_mount`: 6.5 or greater

### Config

Config represents a dictionary with supported LSM BPF file hooks:

* file_open
* mmap_file
* path_truncate
* path_unlink
* path_chmod
* path_chown
* sb_mount

For each file hook the following options are supported:

* `disable` disables detection for current hook. False by default.

FileMon detector supports process allow/deny list for event filtering. It is global for all hooks.
The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).

Config example:

```yaml
file_open:
  disable: false
mmap_file:
  disable: false
path_truncate:
  disable: true
path_unlink:
  disable: true
path_chmod:
  disable: true
path_chown:
  disable: true
sb_mount:
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

Event for `security_path_chown` (file owner change):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 1321712,
    "tid": 1321712,
    "ppid": 1321711,
    "uid": 0,
    "euid": 0,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 2199023255551,
    "cap_effective": 2199023255551,
    "secureexec": "",
    "filename": "chown",
    "binary_path": "/usr/bin/chown",
    "args": "0:0 ./gdb",
    "cgroup_name": "tmux-spawn-dc94c31c-0fb9-42e5-b878-730cf00753d0.scope"
  },
  "hook": {
    "type": "PathChown",
    "path": "/home/fedotoff/gdb",
    "uid": 0,
    "gid": 0
  },
  "timestamp": "2025-07-13T08:41:14.865Z"
}
```

Event for `security_sb_mount` (mount block device):

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 1405679,
    "tid": 1405679,
    "ppid": 1405372,
    "uid": 0,
    "euid": 0,
    "auid": 4294967295,
    "cap_inheritable": 0,
    "cap_permitted": 2199023255551,
    "cap_effective": 2199023255551,
    "secureexec": "",
    "filename": "busybox",
    "binary_path": "/bin/busybox",
    "args": "/dev/sda1 /mnt/hola",
    "cgroup_name": "docker-c13111a07506639ef1a9a6fbe20e23848ea538a606ca913e91fbd4b715ea3385.scope"
  },
  "hook": {
    "type": "SbMount",
    "dev": "/dev/sda1",
    "mnt": "/mnt/hola",
    "flags": 1141528336
  },
  "timestamp": "2025-07-13T09:32:51.206Z"
}
```

Event for `security_mmap_file`:

```json
{
  "type": "FileEvent",
  "process": {
    "pid": 1766332,
    "tid": 1766332,
    "ppid": 1766324,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "date",
    "binary_path": "/usr/bin/date",
    "args": "+%s",
    "cgroup_name": "vte-spawn-7067a0a7-11d2-4d41-9dd5-43fc1ac45d56.scope"
  },
  "hook": {
    "type": "MmapFile",
    "path": "/usr/lib/locale/locale-archive",
    "prot": "PROT_READ",
    "flags": "MAP_SHARED"
  },
  "timestamp": "2025-07-16T18:09:50.559Z"
}
```