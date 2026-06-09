# SysEnumMon

## SysEnumMonEvent

SysEnumMonEvent represents detected system enumeration activity: at least `chain_size`
distinct observations from the watch list were correlated inside one process tree within
the `window_size_sec` window.

Correlation is keyed on the parent PID, so the whole chain belongs to a single parent
process tree. That parent is reported once as the top-level `process` (restored from the
ProcMon Process cache). The event then carries a `chain` of observations, each with its
`entry` and a `timestamp`. The `entry` is tagged by `type`: `Exec` (from `bprm_check_security`,
with the executed `binary`) or `FileOpen` (from `file_open`, with the opened `path`). The
`binary`/`path` is captured in the event itself. For a `path_prefix` rule the `path` is the
actual opened file under the prefix, not the configured prefix. The reported `path` is
truncated to 255 bytes (`MAX_FILE_PREFIX`) in the output event.

```json
{
  "type": "SysEnumMonEvent",
  "process": {
    "start_time": "2026-06-01T11:12:05.590Z",
    "cloned": false,
    "pid": 18983,
    "tid": 18983,
    "ppid": 18904,
    "uid": 1000,
    "euid": 1000,
    "gid": 1000,
    "egid": 1000,
    "auid": 1000,
    "cap_inheritable": "CAP_WAKE_ALARM",
    "cap_permitted": "",
    "cap_effective": "",
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": "/tmp/recon.sh",
    "exec_id": "MTg5ODM6MzYzNDMzNTg0MTMwNA",
    "parent_exec_id": "MTg5MDQ6MzYyOTE1MDAwMDAwMA"
  },
  "chain": [
    {
      "entry": {
        "type": "Exec",
        "binary": "id"
      },
      "timestamp": "2026-06-01T11:12:05.591Z"
    },
    {
      "entry": {
        "type": "FileOpen",
        "path": "/etc/passwd"
      },
      "timestamp": "2026-06-01T11:12:05.592Z"
    },
    {
      "entry": {
        "type": "Exec",
        "binary": "uname"
      },
      "timestamp": "2026-06-01T11:12:05.596Z"
    }
  ],
  "timestamp": "2026-06-01T11:12:05.596Z"
}
```
