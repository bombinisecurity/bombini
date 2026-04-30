# GTFObins

GTFOBins event represents a process information about GTFO binary that tries to spawn privilege shell.

```json
{
  "type": "GTFOBinsEvent",
  "process": {
    "start_time": "2026-04-30T12:11:54.923Z",
    "cloned": false,
    "pid": 99620,
    "tid": 99620,
    "ppid": 99492,
    "uid": 1000,
    "euid": 0,
    "gid": 1000,
    "egid": 0,
    "auid": 1000,
    "cap_inheritable": "",
    "cap_permitted": "ANY_CAPS",
    "cap_effective": "ANY_CAPS",
    "secureexec": "SETUID | SETGID",
    "filename": "xargs",
    "binary_path": "/home/fedotoff/xargs",
    "args": "-a /dev/null sh -p",
    "exec_id": "OTk2MjA6ODcxMjA5OTA0NjA5NDg4",
    "parent_exec_id": "OTk0OTI6ODcxMTk1NzMwNTkzOTI0"
  },
  "timestamp": "2026-04-30T12:11:54.925Z"
}
```
