# FileMon

**FileEvent** represent a collection of events related to file / filesystem operations.

## PathTruncate

Event is triggered when file is truncated by `truncate` syscall.

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

## PathUnlink

Event is triggered when file is deleted.

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

## FileOpen

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

## PathChmod

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

## PathChown

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

## SbMount

Event is triggered when block device is mounted.

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

## MmapFile

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

## FileIoctl

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
