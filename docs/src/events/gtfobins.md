# GTFObins

GTFOBins event represents a process information about GTFO binary that tries to spawn privilege shell.

```json
{
  "process": {
    "args": "-a /dev/null sh",
    "auid": 1000,
    "binary_path": "/usr/bin/xargs",
    "cap_effective": "ALL_CAPS",
    "cap_inheritable": "",
    "cap_permitted": "ALL_CAPS",
    "egid": 0,
    "euid": 0,
    "filename": "xargs",
    "gid": 0,
    "pid": 2159624,
    "ppid": 2159623,
    "secureexec": "",
    "start_time": "2025-12-03T21:56:26.328Z",
    "tid": 2159624,
    "uid": 0
  },
  "timestamp": "2025-12-03T21:56:26.329Z",
  "type": "GTFOBinsEvent"
}
```
