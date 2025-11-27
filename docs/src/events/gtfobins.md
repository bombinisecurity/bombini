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
    "pid": 2275262,
    "ppid": 2275261,
    "secureexec": "",
    "start_time": "2025-11-21T21:32:13.849Z",
    "tid": 2275262,
    "uid": 0
  },
  "timestamp": "2025-11-23T13:48:10.223Z",
  "type": "GTFOBinsEvent"
}
```
