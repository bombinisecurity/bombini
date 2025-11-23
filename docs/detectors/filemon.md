## FileMon

Detector for file operations. Each event has process information. Supported LSM hooks:

* `file_open` hook  provides info about file owner/permissions + permissions with process accessed the file.
* `mmap_file` hook proivdes info about mmaped file: path, protetcion flags.
* `path_truncate` hook provides info about path truncated by truncate syscall.
* `path_unlink` provides info about path being deleted.
* `path_chmod` provides info about changing file permissions.
* `path_chown` provides info about changing file owner.
* `sb_mount` provides info about mounted devices.
* `file_ioctl` provides info about ioctl commands.

### Required Linux Kernel Version

* `file_open`: 6.2 or greater
* `mmap_file`: 6.2 or greater
* `sb_mount`: 6.2 or greater
* `file_ioctl`: 6.2 or greater
* `path_truncate`: 6.8 or greater
* `path_unlink`: 6.8 or greater
* `path_chmod`: 6.8 or greater
* `path_chown`: 6.8 or greater

### Config

Config represents a dictionary with supported LSM BPF file hooks:

* file_open
* mmap_file
* path_truncate
* path_unlink
* path_chmod
* path_chown
* sb_mount
* file_ioctl

For each file hook the following options are supported:

* `enabled` enables detection for current hook. False by default.

**Event filtering**

FileMon detector supports process allow/deny list for event filtering. It is global for all hooks.
The detailed description of process filter config section can be found in ProcMon [config section](procmon.md#config).

Filemon also supports path filtering for hooks:

* file_open
* path_truncate
* path_unlink
* path_chmod
* path_chown
* mmap_file
* file_ioctl

You can specify an allow list of supported paths, using name, prefix, or full path. If path has corresponding name, prefix or equals the provided full path event will be send.

Config example:

```yaml
file_open:
  enabled: true
  path_filter:
    name:
      - .history
      - .bash_history
    prefix:
      - /boot
    path:
      - /etc/passwd
mmap_file:
  enabled: true
path_truncate:
  enabled: false
path_unlink:
  enabled: false
path_chmod:
  enabled: false
path_chown:
  enabled: false
sb_mount:
  enabled: false
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
  "hook": {
    "path": "/tmp/bombini-test-Umxig",
    "type": "PathTruncate"
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-ce492bbece96232d",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "tests-ce492bbece96232d",
    "gid": 0,
    "pid": 2273865,
    "ppid": 2273546,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2273865,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:48:05.016Z",
  "type": "FileEvent"
}
```

Event for `security_path_unlink` (deleting file):

```json
{
  "hook": {
    "path": "/tmp/bombini-test-4XQVT",
    "type": "PathUnlink"
  },
  "process": {
    "args": "/tmp/bombini-test-4XQVT",
    "auid": 1000,
    "binary_path": "/usr/bin/rm",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "rm",
    "gid": 0,
    "pid": 2275200,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2275200,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:48:07.929Z",
  "type": "FileEvent"
}
```

Event for `security_file_open` (opening file):

```json
{
  "hook": {
    "access_mode": "O_RDONLY",
    "creation_flags": "O_NONBLOCK | O_LARGEFILE | O_DIRECTORY",
    "gid": 0,
    "i_mode": "drwxr-xr-x",
    "path": "/etc",
    "type": "FileOpen",
    "uid": 0
  },
  "process": {
    "args": "-lah /etc",
    "auid": 1000,
    "binary_path": "/usr/bin/ls",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "ls",
    "gid": 0,
    "pid": 2274126,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274126,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:23.204Z",
  "type": "FileEvent"
}
```

Event for `security_path_chmod` (file permissions change):

```json
{
  "hook": {
    "i_mode": "?rw-r--r--",
    "path": "/tmp/bombini-test-B3eQr/config/filemon.yaml",
    "type": "PathChmod"
  },
  "process": {
    "args": "+w /tmp/bombini-test-B3eQr/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chmod",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "chmod",
    "gid": 0,
    "pid": 2274989,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274989,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:59.327Z",
  "type": "FileEvent"
}
```

Event for `security_path_chown` (file owner change):

```json
{
  "hook": {
    "gid": 0,
    "path": "/tmp/bombini-test-iAcJI/config/filemon.yaml",
    "type": "PathChown",
    "uid": 0
  },
  "process": {
    "args": "0:0 /tmp/bombini-test-iAcJI/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chown",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "chown",
    "gid": 0,
    "pid": 2275059,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2275059,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:48:02.134Z",
  "type": "FileEvent"
}
```

Event for `security_sb_mount` (mount block device):

```json
{
  "type": "FileEvent",
  "process": {
    "start_time": "2025-07-13T09:32:51.056Z",
    "pid": 1405679,
    "tid": 1405679,
    "ppid": 1405372,
    "uid": 0,
    "euid": 0,
    "egid": 0,
    "gid": 0,
    "auid": 4294967295,
    "cap_inheritable": 0,
    "cap_permitted": 2199023255551,
    "cap_effective": 2199023255551,
    "secureexec": "",
    "filename": "busybox",
    "binary_path": "/bin/busybox",
    "args": "/dev/sda1 /mnt/hola",
    "container_id": "c13111a07506639ef1a9a6fbe20e238"
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
  "hook": {
    "flags": "MAP_SHARED | MAP_PRIVATE",
    "path": "",
    "prot": "PROT_READ | PROT_WRITE",
    "type": "MmapFile"
  },
  "process": {
    "args": "/tmp/bombini-test-DPeG9/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/tail",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "tail",
    "gid": 0,
    "pid": 2274218,
    "ppid": 2273865,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2274218,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:47:25.915Z",
  "type": "FileEvent"
}
```

Event for `security_file_ioctl`:

```json
{
  "hook": {
    "cmd": 16674,
    "i_mode": "crw-rw----",
    "path": "/dev/snd/pcmC1D0p",
    "type": "FileIoctl"
  },
  "process": {
    "args": "",
    "auid": 1000,
    "binary_path": "/usr/bin/pipewire",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "egid": 1000,
    "euid": 1000,
    "filename": "pipewire",
    "gid": 1000,
    "pid": 2292,
    "ppid": 2269,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2292,
    "uid": 1000
  },
  "timestamp": "2025-11-23T13:47:18.989Z",
  "type": "FileEvent"
}
```
