# FileMon

**FileEvent** represent a collection of events related to file / filesystem operations.

## PathTruncate

Event is triggered when file is truncated by `truncate` syscall.

```json
{
  "hook": {
    "path": "/tmp/bombini-test-FdtIU",
    "type": "PathTruncate"
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-2ee26f9bff971ccf",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "tests-2ee26f9bff971ccf",
    "gid": 0,
    "pid": 2158108,
    "ppid": 2157792,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:28.289Z",
    "tid": 2158108,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:56:21.175Z",
  "type": "FileEvent"
}
```

## PathUnlink

Event is triggered when file is deleted.

```json
{
  "hook": {
    "path": "/tmp/bombini-test-QPrRF",
    "type": "PathUnlink"
  },
  "process": {
    "args": "/tmp/bombini-test-QPrRF",
    "auid": 1000,
    "binary_path": "/usr/bin/rm",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "rm",
    "gid": 0,
    "pid": 2159543,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:56:24.047Z",
    "tid": 2159543,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:56:24.048Z",
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
    "pid": 2158523,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:43.272Z",
    "tid": 2158523,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:43.275Z",
  "type": "FileEvent"
}
```

## PathChmod

```json
{
  "hook": {
    "i_mode": "?rw-r--r--",
    "path": "/tmp/bombini-test-3LDzT/config/filemon.yaml",
    "type": "PathChmod"
  },
  "process": {
    "args": "+w /tmp/bombini-test-3LDzT/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chmod",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "chmod",
    "gid": 0,
    "pid": 2159362,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:56:15.410Z",
    "tid": 2159362,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:56:15.411Z",
  "type": "FileEvent"
}
```

## PathChown

```json
{
  "hook": {
    "gid": 0,
    "path": "/tmp/bombini-test-Q1Owh/config/filemon.yaml",
    "type": "PathChown",
    "uid": 0
  },
  "process": {
    "args": "0:0 /tmp/bombini-test-Q1Owh/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chown",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "chown",
    "gid": 0,
    "pid": 2159421,
    "ppid": 2158108,
    "secureexec": "",
    "start_time": "2025-12-03T21:56:18.293Z",
    "tid": 2159421,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:56:18.295Z",
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
    "path": "/tmp/bombini-test-EZSO2/config/filemon.yaml",
    "prot": "PROT_READ | PROT_WRITE",
    "type": "MmapFile"
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-2ee26f9bff971ccf",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "tests-2ee26f9bff971ccf",
    "gid": 0,
    "pid": 2158108,
    "ppid": 2157792,
    "secureexec": "",
    "start_time": "2025-12-03T21:55:28.289Z",
    "tid": 2158108,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:55:38.884Z",
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
    "pid": 2238,
    "ppid": 2219,
    "secureexec": "",
    "start_time": "2025-11-26T14:28:30.379Z",
    "tid": 2238,
    "uid": 1000
  },
  "timestamp": "2025-12-03T21:55:34.500Z",
  "type": "FileEvent"
}
```
