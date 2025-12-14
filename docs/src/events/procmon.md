# ProcMon

## ProcessExec

ProcessExec event represents a new executed binary (execve).

```json
{
  "parent": {
    "args": "-u -2 -f /usr/share/byobu/profiles/tmuxrc new-session -n - /usr/bin/byobu-shell",
    "auid": 1000,
    "binary_path": "/usr/bin/tmux",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "filename": "tmux",
    "gid": 1000,
    "pid": 72741,
    "ppid": 2219,
    "secureexec": "",
    "start_time": "2025-11-26T17:42:02.112Z",
    "tid": 72741,
    "uid": 1000
  },
  "process": {
    "args": "-c byobu-status tmux_left",
    "auid": 1000,
    "binary_path": "/usr/bin/dash",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "filename": "dash",
    "gid": 1000,
    "pid": 6700,
    "ppid": 72741,
    "secureexec": "",
    "start_time": "2025-12-11T11:45:47.773Z",
    "tid": 6700,
    "uid": 1000
  },
  "timestamp": "2025-12-11T11:45:47.773Z",
  "type": "ProcessExec"
}
```

### IMA Binary Hash

Process information can be enriched with binary hashes collected from IMA.

```json
{
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
    "args": "-lah",
    "auid": 1000,
    "binary_ima_hash": "sha256:0148f5ab3062a905281d8deb9645363da5131011c9e7b6dcaa38b504e41b68ea",
    "binary_path": "/usr/bin/ls",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "ls",
    "gid": 0,
    "pid": 7259,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:12.653Z",
    "tid": 7259,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:12.653Z",
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
    "args": "fileless-exec-test",
    "auid": 1000,
    "binary_path": "/memfd:fileless-exec-test (deleted)",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "memfd:fileless-exec-test",
    "gid": 0,
    "pid": 7206,
    "ppid": 6576,
    "secureexec": "FILELESS_EXEC",
    "start_time": "2025-12-11T11:46:10.107Z",
    "tid": 7206,
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:10.107Z",
  "type": "ProcessExec"
}
```

## ProcessClone

ProcessClone represents a process creation with fork() or clone() syscall types.

```json
{
  "parent": {
    "args": "-u -2 -f /usr/share/byobu/profiles/tmuxrc new-session -n - /usr/bin/byobu-shell",
    "auid": 1000,
    "binary_path": "/usr/bin/tmux",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "filename": "tmux",
    "gid": 1000,
    "pid": 72741,
    "ppid": 2219,
    "secureexec": "",
    "start_time": "2025-11-26T17:42:02.112Z",
    "tid": 72741,
    "uid": 1000
  },
  "process": {
    "args": "-u -2 -f /usr/share/byobu/profiles/tmuxrc new-session -n - /usr/bin/byobu-shell",
    "auid": 0,
    "binary_path": "/usr/bin/tmux",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": true,
    "egid": 1000,
    "euid": 1000,
    "filename": "tmux",
    "gid": 1000,
    "pid": 7243,
    "ppid": 72741,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:11.813Z",
    "tid": 7243,
    "uid": 1000
  },
  "timestamp": "2025-12-11T11:46:11.813Z",
  "type": "ProcessClone"
}
```

## ProcessExit

ProcessExit event represents an exited process.

```json
{
  "parent": {
    "args": "/usr/bin/byobu-status tmux_right",
    "auid": 1000,
    "binary_ima_hash": "sha256:86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42",
    "binary_path": "/usr/bin/dash",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": false,
    "egid": 1000,
    "euid": 1000,
    "filename": "dash",
    "gid": 1000,
    "pid": 7248,
    "ppid": 7243,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:11.845Z",
    "tid": 7248,
    "uid": 1000
  },
  "process": {
    "args": "/usr/bin/byobu-status tmux_right",
    "auid": 0,
    "binary_path": "/usr/bin/dash",
    "cap_effective": "",
    "cap_inheritable": "",
    "cap_permitted": "",
    "cloned": true,
    "egid": 1000,
    "euid": 1000,
    "filename": "dash",
    "gid": 1000,
    "pid": 7250,
    "ppid": 7248,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:11.849Z",
    "tid": 7250,
    "uid": 1000
  },
  "timestamp": "2025-12-11T11:46:11.850Z",
  "type": "ProcessExit"
}
```

## ProcessEvents

ProcessEvents represent a collection of events somehow related to privilege escalation

### Setuid

```json
{
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
    "args": "-u nobody true",
    "auid": 1000,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "sudo",
    "gid": 0,
    "pid": 7425,
    "ppid": 6576,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:20.687Z",
    "tid": 7425,
    "uid": 0
  },
  "process_event": {
    "euid": 0,
    "flags": "LSM_SETID_RES",
    "fsuid": 0,
    "type": "Setuid",
    "uid": 0
  },
  "timestamp": "2025-12-11T11:46:20.693Z",
  "type": "ProcessEvent"
}
```

### Setcaps

```json
{
  "parent": {
    "args": "capsh --caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "auid": 0,
    "binary_path": "/usr/bin/sudo",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": true,
    "egid": 0,
    "euid": 0,
    "filename": "sudo",
    "gid": 0,
    "pid": 7381,
    "ppid": 7380,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:18.013Z",
    "tid": 7381,
    "uid": 0
  },
  "process": {
    "args": "--caps=cap_sys_admin=ep cap_net_raw=ep -- -c id",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "capsh",
    "gid": 0,
    "pid": 7382,
    "ppid": 7381,
    "secureexec": "",
    "start_time": "2025-12-11T11:46:18.016Z",
    "tid": 7382,
    "uid": 0
  },
  "process_event": {
    "effective": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "inheritable": "",
    "permitted": "CAP_NET_RAW | CAP_SYS_ADMIN",
    "type": "Setcaps"
  },
  "timestamp": "2025-12-11T11:46:18.016Z",
  "type": "ProcessEvent"
}
```

### Prctl

```json
{
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
    "pid": 217149,
    "ppid": 216910,
    "secureexec": "",
    "start_time": "2025-12-14T11:16:03.806Z",
    "tid": 217149,
    "uid": 0
  },
  "process": {
    "args": "--keep=1 -- -c echo KEEPCAPS enabled",
    "auid": 1000,
    "binary_path": "/usr/sbin/capsh",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "capsh",
    "gid": 0,
    "pid": 217438,
    "ppid": 217149,
    "secureexec": "",
    "start_time": "2025-12-14T11:16:36.901Z",
    "tid": 217438,
    "uid": 0
  },
  "process_event": {
    "cmd": {
      "PrSetKeepCaps": 1
    },
    "type": "Prctl"
  },
  "timestamp": "2025-12-14T11:16:36.903Z",
  "type": "ProcessEvent"
}
```

### CreateUserNs

```json
{
  "parent": null,
  "process": {
    "args": "-U",
    "auid": 1000,
    "binary_path": "/usr/bin/unshare",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "cloned": false,
    "egid": 0,
    "euid": 0,
    "filename": "unshare",
    "gid": 0,
    "pid": 217376,
    "ppid": 217149,
    "secureexec": "",
    "start_time": "2025-12-14T11:16:29.111Z",
    "tid": 217376,
    "uid": 0
  },
  "process_event": {
    "type": "CreateUserNs"
  },
  "timestamp": "2025-12-14T11:16:29.113Z",
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
      "args": "./evets.log"
    },
    "mode": "PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS"
  },
  "timestamp": "2025-12-11T12:07:20.712Z"
}
```
