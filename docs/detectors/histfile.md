## HistFile

HistFile detector detects cases when user stops writing bash
history to `~/.bash_history`. It can be done using this commands:

```bash
export HISTFILESIZE=0
export HISTSIZE=0
```

Detector attaches to `/bin/bash` `readline` func with uretprobe and uses **lpm_trie**
map to check for commands above.

### Required Linux Kernel Version

5.15 or greater

### Config

This detector has no config

### Event

```json
{
  "type": "HistFileEvent",
  "process": {
    "pid": 729714,
    "tid": 729714,
    "ppid": 462192,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": "",
    "cgroup_name": "tmux-spawn-b96bf9ec-bfa7-4021-9b9b-26e4a6e832e9.scope"
  },
  "command": "export HISTFILESIZE=0 && cat /etc/passwd",
  "timestamp": "2025-05-31T10:05:01.173Z"
}
```
