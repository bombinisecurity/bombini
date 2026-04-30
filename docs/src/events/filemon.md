# FileMon

**FileEvent** represent a collection of events related to file / filesystem operations.

## PathTruncate

Event is triggered when file is truncated by `truncate` syscall.

```json
{
  "blocked": false,
  "hook": {
    "path": "/tmp/bombini-test-ouG0p/bombini-test-truncate",
    "type": "PathTruncate"
  },
  "parent": {
    "args": "test --release --features=examples -- -q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "filename": "cargo",
    "gid": 0,
    "parent_exec_id": "Mjk1NTc6ODYxMTYwMTYwMDAwMDAw",
    "pid": 29558,
    "ppid": 29557,
    "secureexec": "",
    "start_time": "2026-04-30T09:24:25.178Z",
    "tid": 29558,
    "uid": 0
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "rule": "TruncateTestRule",
  "timestamp": "2026-04-30T09:25:40.554Z",
  "type": "FileEvent"
}
```

## PathUnlink

Event is triggered when file is deleted.

```json
{
  "blocked": false,
  "hook": {
    "path": "/tmp/bombini-test-QCS8G/bombini-test-unlink",
    "type": "PathUnlink"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "process": {
    "args": "/tmp/bombini-test-QCS8G/bombini-test-unlink",
    "auid": 1000,
    "binary_path": "/usr/bin/rm",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzA0NTU6ODYxMjM3OTAxMTk2NDY0",
    "filename": "rm",
    "gid": 0,
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "pid": 30455,
    "ppid": 30195,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:42.919Z",
    "tid": 30455,
    "uid": 0
  },
  "rule": "UnlinkTestRule",
  "timestamp": "2026-04-30T09:25:42.920Z",
  "type": "FileEvent"
}
```

## PathSymlink

Event is triggered when symbolic link is created.

```json
{
  "blocked": false,
  "hook": {
    "link_path": "/tmp/bombini-test-LcAq6/bombini_test_symlink_1",
    "old_path": "/tmp/bombini-test-symlink-F7rij",
    "type": "PathSymlink"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "process": {
    "args": "-s /tmp/bombini-test-symlink-F7rij /tmp/bombini-test-LcAq6/bombini_test_symlink_1",
    "auid": 1000,
    "binary_path": "/usr/bin/ln",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAzOTA6ODYxMjMzMjc4Mzg5MjUy",
    "filename": "ln",
    "gid": 0,
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "pid": 30390,
    "ppid": 30195,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:38.296Z",
    "tid": 30390,
    "uid": 0
  },
  "rule": "SymlinkTestRule",
  "timestamp": "2026-04-30T09:25:38.297Z",
  "type": "FileEvent"
}
```

## FileOpen

```json
{
  "blocked": true,
  "hook": {
    "access_mode": "O_WRONLY",
    "creation_flags": "O_CREAT | O_TRUNC | O_LARGEFILE",
    "gid": 0,
    "i_mode": "-rw-r--r--",
    "path": "/tmp/bombini-test-lJKrO/config/filemon.yaml",
    "type": "FileOpen",
    "uid": 0
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/sandbox-b2a60a831c22e140",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzA5OTc6ODYxMjgzMjQwMDAwMDAw",
    "filename": "sandbox-b2a60a831c22e140",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30997,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:26:28.258Z",
    "tid": 30997,
    "uid": 0
  },
  "process": {
    "args": "-c echo 'Hello' > /tmp/bombini-test-lJKrO/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/dash",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzEwMjA6ODYxMjg0NzQ2Nzc2ODU0",
    "filename": "dash",
    "gid": 0,
    "parent_exec_id": "MzA5OTc6ODYxMjgzMjQwMDAwMDAw",
    "pid": 31020,
    "ppid": 30997,
    "secureexec": "",
    "start_time": "2026-04-30T09:26:29.765Z",
    "tid": 31020,
    "uid": 0
  },
  "rule": "OpenTestSandBoxRule",
  "timestamp": "2026-04-30T09:26:29.765Z",
  "type": "FileEvent"
}
```

## PathChmod

```json
{
  "blocked": false,
  "hook": {
    "i_mode": "?rw-r--r--",
    "path": "/tmp/bombini-test-E7eJb/config/filemon.yaml",
    "type": "PathChmod"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "process": {
    "args": "+w /tmp/bombini-test-E7eJb/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chmod",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAzMTg6ODYxMjI3NzI0MzU5NjIy",
    "filename": "chmod",
    "gid": 0,
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "pid": 30318,
    "ppid": 30195,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:32.742Z",
    "tid": 30318,
    "uid": 0
  },
  "rule": "ChmodTestRule",
  "timestamp": "2026-04-30T09:25:32.744Z",
  "type": "FileEvent"
}
```

## PathChown

```json
{
  "blocked": false,
  "hook": {
    "gid": 0,
    "path": "/tmp/bombini-test-JbqTN/config/filemon.yaml",
    "type": "PathChown",
    "uid": 0
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "process": {
    "args": "0:0 /tmp/bombini-test-JbqTN/config/filemon.yaml",
    "auid": 1000,
    "binary_path": "/usr/bin/chown",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAzNTk6ODYxMjMwODg5NzM5NDcz",
    "filename": "chown",
    "gid": 0,
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "pid": 30359,
    "ppid": 30195,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:35.908Z",
    "tid": 30359,
    "uid": 0
  },
  "rule": "ChownTestRule",
  "timestamp": "2026-04-30T09:25:35.910Z",
  "type": "FileEvent"
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
    "exec_id": "MzAzNTk6ODYxMjMwODg5NzM5NDcz",
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
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
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "container_id": "161287b604973779d82648fbbf6a418"
  },
  "hook": {
    "type": "SbMount",
    "dev": "/dev/sda1",
    "mnt": "/mnt",
    "flags": 1306860944
  },
  "blocked": false,
  "timestamp": "2025-12-11T13:07:53.637Z"
}
```

## MmapFile

```json
{
  "blocked": false,
  "hook": {
    "flags": "MAP_SHARED",
    "path": "/tmp/bombini-test-VB2Ri/config/filemon.yaml",
    "prot": "PROT_READ | PROT_WRITE",
    "type": "MmapFile"
  },
  "parent": {
    "args": "test --release --features=examples -- -q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "filename": "cargo",
    "gid": 0,
    "parent_exec_id": "Mjk1NTc6ODYxMTYwMTYwMDAwMDAw",
    "pid": 29558,
    "ppid": 29557,
    "secureexec": "",
    "start_time": "2026-04-30T09:24:25.178Z",
    "tid": 29558,
    "uid": 0
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "rule": "MmapFileTestRule",
  "timestamp": "2026-04-30T09:25:27.599Z",
  "type": "FileEvent"
}
```

## FileIoctl

```json
{
  "blocked": false,
  "hook": {
    "cmd": 4712,
    "i_mode": "brw-rw----",
    "path": "/dev/loop0",
    "type": "FileIoctl"
  },
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/filemon-39a009b56d273b88",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "Mjk1NTg6ODYxMTYwMTYwMDAwMDAw",
    "pid": 30195,
    "ppid": 29558,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:24.928Z",
    "tid": 30195,
    "uid": 0
  },
  "process": {
    "args": "-l",
    "auid": 1000,
    "binary_path": "/usr/sbin/fdisk",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "MzAyMTk6ODYxMjIwOTE5NzQxMzc5",
    "filename": "fdisk",
    "gid": 0,
    "parent_exec_id": "MzAxOTU6ODYxMjE5OTEwMDAwMDAw",
    "pid": 30219,
    "ppid": 30195,
    "secureexec": "",
    "start_time": "2026-04-30T09:25:25.938Z",
    "tid": 30219,
    "uid": 0
  },
  "rule": "IoctlTestRule",
  "timestamp": "2026-04-30T09:25:25.941Z",
  "type": "FileEvent"
}
```
