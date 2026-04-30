# ProcMon

## ProcessExec

ProcessExec event represents a new executed binary (execve).

```json
{
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
    "exec_id": "ODQxMjQ6ODY5NDYyNTkwMDAwMDAw",
    "filename": "filemon-39a009b56d273b88",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84124,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:42:47.608Z",
    "tid": 84124,
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
    "exec_id": "ODQxNDU6ODY5NDYzNTk4MDM5Mzcy",
    "filename": "fdisk",
    "gid": 0,
    "parent_exec_id": "ODQxMjQ6ODY5NDYyNTkwMDAwMDAw",
    "pid": 84145,
    "ppid": 84124,
    "secureexec": "",
    "start_time": "2026-04-30T11:42:48.616Z",
    "tid": 84145,
    "uid": 0
  },
  "timestamp": "2026-04-30T11:42:48.616Z",
  "type": "ProcessExec"
}
```

### IMA Binary Hash

Process information can be enriched with binary hashes collected from IMA.

```json
{
  "parent": {
    "args": "/home/fedotoff/.vscode/extensions/google.geminicodeassist-2.75.0/agent/a2a-server.mjs",
    "auid": 1000,
    "binary_path": "/usr/share/code/code",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "ODQ3NDk6ODY5NTExOTkwMDAwMDAw",
    "filename": "code",
    "gid": 1000,
    "parent_exec_id": "MTUxNjY6ODYwNzczMjYwMDAwMDAw",
    "pid": 84749,
    "ppid": 15166,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:37.008Z",
    "tid": 84749,
    "uid": 1000
  },
  "process": {
    "args": "--version",
    "auid": 1000,
    "binary_ima_hash": "sha256:2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668",
    "binary_path": "/usr/bin/git",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "ODQ3ODM6ODY5NTEyNjI5ODAyMzQ5",
    "filename": "git",
    "gid": 1000,
    "parent_exec_id": "ODQ3NDk6ODY5NTExOTkwMDAwMDAw",
    "pid": 84783,
    "ppid": 84749,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:37.648Z",
    "tid": 84783,
    "uid": 1000
  },
  "timestamp": "2026-04-30T11:43:37.648Z",
  "type": "ProcessExec"
}
```

### Fileless Execution

Event has information if no file used for process execution (memfd_create).

```json
{
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/procmon-ffa17fc59f5de4b8",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "filename": "procmon-ffa17fc59f5de4b8",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84662,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:32.788Z",
    "tid": 84662,
    "uid": 0
  },
  "process": {
    "args": "fileless-exec-test",
    "auid": 1000,
    "binary_path": "/memfd:fileless-exec-test (deleted)",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ3NDY6ODY5NTExNjgyNTg4OTc4",
    "filename": "memfd:fileless-exec-test",
    "gid": 0,
    "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "pid": 84746,
    "ppid": 84662,
    "secureexec": "FILELESS_EXEC",
    "start_time": "2026-04-30T11:43:36.701Z",
    "tid": 84746,
    "uid": 0
  },
  "timestamp": "2026-04-30T11:43:36.701Z",
  "type": "ProcessExec"
}
```

## ProcessClone

ProcessClone represents a process creation with fork() or clone() syscall types.

```json
{
  "parent": {
    "args": "",
    "auid": 1000,
    "binary_path": "/usr/share/code/code",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "MTUxNjY6ODYwNzczMjYwMDAwMDAw",
    "filename": "code",
    "gid": 1000,
    "parent_exec_id": "MTQ5NzM6ODYwNzY4NDkwMDAwMDAw",
    "pid": 15166,
    "ppid": 14973,
    "secureexec": "",
    "start_time": "2026-04-30T09:17:58.278Z",
    "tid": 15166,
    "uid": 1000
  },
  "process": {
    "args": "",
    "auid": 0,
    "binary_path": "/usr/share/code/code",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": true,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "ODQ3NDg6ODY5NTExOTU5NjkyMTA5",
    "filename": "code",
    "gid": 1000,
    "parent_exec_id": "MTUxNjY6ODYwNzczMjYwMDAwMDAw",
    "pid": 84748,
    "ppid": 15166,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:36.978Z",
    "tid": 84748,
    "uid": 1000
  },
  "timestamp": "2026-04-30T11:43:36.978Z",
  "type": "ProcessClone"
}
```

## ProcessExit

ProcessExit event represents an exited process.

```json
{
  "parent": {
    "args": "",
    "auid": 1000,
    "binary_path": "/usr/share/code/code",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "MTUxNjY6ODYwNzczMjYwMDAwMDAw",
    "filename": "code",
    "gid": 1000,
    "parent_exec_id": "MTQ5NzM6ODYwNzY4NDkwMDAwMDAw",
    "pid": 15166,
    "ppid": 14973,
    "secureexec": "",
    "start_time": "2026-04-30T09:17:58.278Z",
    "tid": 15166,
    "uid": 1000
  },
  "process": {
    "args": "/home/fedotoff/.vscode/extensions/google.geminicodeassist-2.75.0/agent/a2a-server.mjs",
    "auid": 1000,
    "binary_path": "/usr/share/code/code",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "exec_id": "ODQ2ODk6ODY5NTA4NDIwMDAwMDAw",
    "filename": "code",
    "gid": 1000,
    "parent_exec_id": "MTUxNjY6ODYwNzczMjYwMDAwMDAw",
    "pid": 84689,
    "ppid": 15166,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:33.438Z",
    "tid": 84689,
    "uid": 1000
  },
  "timestamp": "2026-04-30T11:43:36.961Z",
  "type": "ProcessExit"
}
```

## ProcessEvents

ProcessEvents represent a collection of events somehow related to privilege escalation

### Setuid

```json
{
  "blocked": false,
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/procmon-ffa17fc59f5de4b8",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "filename": "procmon-ffa17fc59f5de4b8",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84662,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:32.788Z",
    "tid": 84662,
    "uid": 0
  },
  "process": {
    "args": "-u nobody true",
    "auid": 1000,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ5MTA6ODY5NTIwMTc5ODU0ODA5",
    "filename": "sudo",
    "gid": 0,
    "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "pid": 84910,
    "ppid": 84662,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:45.198Z",
    "tid": 84910,
    "uid": 0
  },
  "process_event": {
    "euid": 0,
    "flags": "LSM_SETID_RES",
    "fsuid": 0,
    "type": "Setuid",
    "uid": 0
  },
  "rule": "ProcMonSetuid",
  "timestamp": "2026-04-30T11:43:45.201Z",
  "type": "ProcessEvent"
}
```

### Setgid

```json
{
  "blocked": false,
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/procmon-ffa17fc59f5de4b8",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "filename": "procmon-ffa17fc59f5de4b8",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84662,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:32.788Z",
    "tid": 84662,
    "uid": 0
  },
  "process": {
    "args": "-u nobody true",
    "auid": 1000,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ4ODM6ODY5NTE4NTE2MDAyMDk5",
    "filename": "sudo",
    "gid": 0,
    "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "pid": 84883,
    "ppid": 84662,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:43.534Z",
    "tid": 84883,
    "uid": 0
  },
  "process_event": {
    "egid": 0,
    "flags": "LSM_SETID_RES",
    "fsgid": 0,
    "gid": 0,
    "type": "Setgid"
  },
  "rule": "ProcMonSetgid",
  "timestamp": "2026-04-30T11:43:43.539Z",
  "type": "ProcessEvent"
}
```

### Setcaps

```json
{
  "blocked": false,
  "parent": {
    "args": "capsh --caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "auid": 0,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": true,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ4NjA6ODY5NTE2NjM0MzkyMTcw",
    "filename": "sudo",
    "gid": 0,
    "parent_exec_id": "ODQ4NTk6ODY5NTE2NjI2Nzc5Mzg1",
    "pid": 84860,
    "ppid": 84859,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:41.652Z",
    "tid": 84860,
    "uid": 0
  },
  "process": {
    "args": "--caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ4NjE6ODY5NTE2NjM1NzgwNzAx",
    "filename": "capsh",
    "gid": 0,
    "parent_exec_id": "ODQ4NjA6ODY5NTE2NjM0MzkyMTcw",
    "pid": 84861,
    "ppid": 84860,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:41.654Z",
    "tid": 84861,
    "uid": 0
  },
  "process_event": {
    "effective": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "inheritable": "",
    "permitted": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "type": "Setcaps"
  },
  "rule": "ProcMonSetcaps",
  "timestamp": "2026-04-30T11:43:41.654Z",
  "type": "ProcessEvent"
}
```

### Prctl

```json
{
  "blocked": false,
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/procmon-ffa17fc59f5de4b8",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "filename": "procmon-ffa17fc59f5de4b8",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84662,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:32.788Z",
    "tid": 84662,
    "uid": 0
  },
  "process": {
    "args": "--keep=1 -- -c echo KEEPCAPS enabled",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ4MTg6ODY5NTE0OTczMjgxMTk1",
    "filename": "capsh",
    "gid": 0,
    "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "pid": 84818,
    "ppid": 84662,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:39.991Z",
    "tid": 84818,
    "uid": 0
  },
  "process_event": {
    "cmd": {
      "PrSetKeepCaps": 1
    },
    "type": "Prctl"
  },
  "rule": "ProcMonPrctl",
  "timestamp": "2026-04-30T11:43:39.992Z",
  "type": "ProcessEvent"
}
```

### CreateUserNs

```json
{
  "blocked": false,
  "parent": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 1000,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/procmon-ffa17fc59f5de4b8",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "filename": "procmon-ffa17fc59f5de4b8",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84662,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:32.788Z",
    "tid": 84662,
    "uid": 0
  },
  "process": {
    "args": "-U",
    "auid": 1000,
    "binary_path": "/usr/bin/unshare",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODQ3MjQ6ODY5NTEwNDE4NzgyMjAx",
    "filename": "unshare",
    "gid": 0,
    "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
    "pid": 84724,
    "ppid": 84662,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:35.437Z",
    "tid": 84724,
    "uid": 0
  },
  "process_event": {
    "type": "CreateUserNs"
  },
  "rule": "ProcMonCreateUserNs",
  "timestamp": "2026-04-30T11:43:35.437Z",
  "type": "ProcessEvent"
}
```

### PtraceAccessCheck

```json
{
  "type": "ProcessEvent",
  "process": {
    "start_time": "2025-12-11T12:07:20.621Z",
    "cloned": false,
    "pid": 26539,
    "tid": 26539,
    "ppid": 72885,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "gdb",
    "binary_path": "/usr/bin/gdb",
    "exec_id": "ODQ5MzA6ODY5NTIxMDYwMDAwMDAw",
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "args": "attach -p 26029"
  },
  "parent": {
    "start_time": "2025-11-26T17:42:04.042Z",
    "cloned": false,
    "pid": 72885,
    "tid": 72885,
    "ppid": 72741,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "zsh",
    "binary_path": "/usr/bin/zsh",
    "exec_id": "ODUwMDA6ODY5NTI0OTM4NjAzNzMz",
    "parent_exec_id": "ODQ5MzA6ODY5NTIxMDYwMDAwMDAw",
    "args": ""
  },
  "process_event": {
    "type": "PtraceAccessCheck",
    "child": {
      "start_time": "2025-12-11T12:06:49.791Z",
      "cloned": false,
      "pid": 26029,
      "tid": 26029,
      "ppid": 2230022,
      "uid": 1000,
      "euid": 1000,
      "gid": 1000,
      "egid": 1000,
      "auid": 1000,
      "cap_inheritable": "",
      "cap_permitted": "",
      "cap_effective": "",
      "secureexec": "",
      "filename": "vim.basic",
      "binary_path": "/usr/bin/vim.basic",
      "exec_id": "ODQ3MjQ6ODY5NTEwNDE4NzgyMjAx",
      "parent_exec_id": "ODQ2NjI6ODY5NTA3NzcwMDAwMDAw",
      "args": "./evets.log"
    },
    "mode": "PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS"
  },
  "blocked": false,
  "timestamp": "2025-12-11T12:07:20.712Z"
}
```

### BprmCheck

```json
{
  "blocked": true,
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
    "exec_id": "ODQ5MzA6ODY5NTIxMDYwMDAwMDAw",
    "filename": "sandbox-b2a60a831c22e140",
    "gid": 0,
    "parent_exec_id": "ODQxMDU6ODY5NDYyNDQwMDAwMDAw",
    "pid": 84930,
    "ppid": 84105,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:46.078Z",
    "tid": 84930,
    "uid": 0
  },
  "process": {
    "args": "-q --show-output --test-threads 1 test_6_2_ test_6_8_",
    "auid": 0,
    "binary_path": "/home/fedotoff/bombini/target/release/deps/sandbox-b2a60a831c22e140",
    "cap_effective": "ANY_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cloned": true,
    "egid": 0,
    "euid": 0,
    "exec_id": "ODUwMDA6ODY5NTI0OTM4NjAzNzMz",
    "filename": "sandbox-b2a60a831c22e140",
    "gid": 0,
    "parent_exec_id": "ODQ5MzA6ODY5NTIxMDYwMDAwMDAw",
    "pid": 85000,
    "ppid": 84930,
    "secureexec": "",
    "start_time": "2026-04-30T11:43:49.957Z",
    "tid": 85000,
    "uid": 0
  },
  "process_event": {
    "binary": "/tmp/bombini-test-qvhme/ls",
    "type": "BprmCheck"
  },
  "rule": "BprmCheckTestRule",
  "timestamp": "2026-04-30T11:43:49.957Z",
  "type": "ProcessEvent"
}
```
