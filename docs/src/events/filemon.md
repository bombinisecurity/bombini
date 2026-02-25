# FileMon

**FileEvent** represent a collection of events related to file / filesystem operations.

## PathTruncate

Event is triggered when file is truncated by `truncate` syscall.

```json
{
  "hook": {
    "path": "/tmp/bombini-test-U28D8",
    "type": "PathTruncate"
  },
  "parent": {
    "args": "test --release --features=examples -- -q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "cargo",
    "gid": 0,
    "pid": 5914,
    "ppid": 5913,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:09.002Z",
    "tid": 5914,
    "uid": 0
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:28.965Z",
  "type": "FileEvent",
  "rule": "TruncateTestRule"
}
```

## PathUnlink

Event is triggered when file is deleted.

```json
{
  "hook": {
    "path": "/tmp/bombini-test-5R3Uq",
    "type": "PathUnlink"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "/tmp/bombini-test-5R3Uq",
    "auid": 1000,
    "binary_path": "/usr/bin/rm",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "rm",
    "gid": 0,
    "pid": 7656,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:31.741Z",
    "tid": 7656,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:31.742Z",
  "type": "FileEvent",
  "rule": "UnlinkTestRule"
}
```

## PathSymlink

Event is triggered when symbolic link is created.

```json
{
  "type": "FileEvent",
  "process": {
    "start_time": "2026-01-23T08:15:16.135Z",
    "cloned": false,
    "pid": 1944,
    "tid": 1944,
    "ppid": 1806,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "ln",
    "binary_path": "/usr/bin/ln",
    "args": "-s /etc/passwd /home/lima.linux/not_a_passwrod"
  },
  "parent": {
    "start_time": "2026-01-23T08:12:56.496Z",
    "cloned": false,
    "pid": 1806,
    "tid": 1806,
    "ppid": 1711,
    "uid": 535357931,
    "euid": 535357931,
    "gid": 1000,
    "egid": 1000,
    "auid": 535357931,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": "--login"
  },
  "hook": {
    "type": "PathSymlink",
    "link_path": "/home/lima.linux/not_a_passwrod",
    "old_path": "/etc/passwd"
  },
  "timestamp": "2026-01-23T08:15:16.135Z",
  "rule": "SymlinkTestRule"
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
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "-lah /etc",
    "auid": 1000,
    "binary_path": "/usr/bin/ls",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "ls",
    "gid": 0,
    "pid": 6897,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:57.090Z",
    "tid": 6897,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:45:57.094Z",
  "type": "FileEvent",
  "rule": "OpenTestRule"
}
```

## PathChmod

```json
{
  "hook": {
    "i_mode": "?rw-r--r--",
    "path": "/tmp/bombini-test-S6lD9/config/filemon.yaml",
    "type": "PathChmod"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "+w /tmp/bombini-test-S6lD9/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chmod",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "chmod",
    "gid": 0,
    "pid": 7491,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:23.486Z",
    "tid": 7491,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:23.488Z",
  "type": "FileEvent",
  "rule": "ChmodTestRule"
}
```

## PathChown

```json
{
  "hook": {
    "gid": 0,
    "path": "/tmp/bombini-test-49KFg/config/filemon.yaml",
    "type": "PathChown",
    "uid": 0
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "process": {
    "args": "0:0 /tmp/bombini-test-49KFg/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chown",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "chown",
    "gid": 0,
    "pid": 7552,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:26.188Z",
    "tid": 7552,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:26.190Z",
  "type": "FileEvent",
  "rule": "ChownTestRule"
}
```

## SbMount

Event is triggered when block device is mounted.

```json
{
  "type": "FileEvent",
  "process": {
    "start_time": "2025-12-11T13:07:53.637Z",
    "cloned": false,
    "pid": 83289,
    "tid": 83289,
    "ppid": 83119,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 4294967295,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "busybox",
    "binary_path": "/bin/busybox",
    "args": "/dev/sda1 /mnt",
    "container_id": "161287b604973779d82648fbbf6a418"
  },
  "parent": {
    "start_time": "2025-12-11T13:07:46.743Z",
    "cloned": false,
    "pid": 83119,
    "tid": 83119,
    "ppid": 83097,
    "uid": 0,
    "euid": 0,
    "gid": 0,
    "egid": 0,
    "auid": 4294967295,
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cap_effective": "ALL_CAPS",
    "secureexec": "",
    "filename": "busybox",
    "binary_path": "/bin/busybox",
    "args": "",
    "container_id": "161287b604973779d82648fbbf6a418"
  },
  "hook": {
    "type": "SbMount",
    "dev": "/dev/sda1",
    "mnt": "/mnt",
    "flags": 1306860944
  },
  "timestamp": "2025-12-11T13:07:53.637Z"
}
```

## MmapFile

```json
{
  "hook": {
    "flags": "MAP_SHARED | MAP_PRIVATE",
    "path": "/tmp/bombini-test-kpUpE/config/filemon.yaml",
    "prot": "PROT_READ | PROT_WRITE",
    "type": "MmapFile"
  },
  "parent": {
    "args": "test --release --features=examples -- -q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "cargo",
    "gid": 0,
    "pid": 5914,
    "ppid": 5913,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:09.002Z",
    "tid": 5914,
    "uid": 0
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/tests-539c5f7a878130ef",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "tests-539c5f7a878130ef",
    "gid": 0,
    "pid": 6576,
    "ppid": 5914,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:41.992Z",
    "tid": 6576,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:45:52.856Z",
  "type": "FileEvent"
}
```

## FileIoctl

```json
{
  "hook": {
    "cmd": 3221775552,
    "i_mode": "crw-rw----",
    "path": "/dev/dri/card1",
    "type": "FileIoctl"
  },
  "parent": {
    "args": "--user",
    "auid": 1000,
    "binary_path": "/usr/lib/systemd/systemd",
    "cap_effective": "CAP_WAKE_ALARM",
    "cap_inheritable": "CAP_WAKE_ALARM",
    "cap_permitted": "CAP_WAKE_ALARM",
    "cloned": false,
    "container_id": "1000.slice/user@1000.service/in",
    "egid": 1000,
    "euid": 1000,
    "filename": "systemd",
    "gid": 1000,
    "pid": 2219,
    "ppid": 1,
    "secureexec": "",
    "start_time": "2025-11-26T14:28:37.112Z",
    "tid": 2219,
    "uid": 1000
  },
  "process": {
    "args": "",
    "auid": 1000,
    "binary_path": "/usr/bin/gnome-shell",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "filename": "gnome-shell",
    "gid": 1000,
    "pid": 2476,
    "ppid": 2219,
    "secureexec": "",
    "start_time": "2025-11-26T14:28:37.942Z",
    "tid": 2476,
    "uid": 1000
  },
  "timestamp": "2025-12-11T11:45:48.084Z",
  "type": "FileEvent",
  "rule": "IoctlTestRule"
}

```
