## HistFile

HistFile detector detects cases when user stops writing bash
history to `~/.bash_history`. It can be done using this commands:

```bash
export HISTFILESIZE=0
export HISTSIZE=0
```

Detector attaches to `/bin/bash` `readline` func with uretprobe and uses **lpm_trie**
map to check for commands above.

### Config

This detector has no config

### Event

```json
{
  "type": "HistFileEvent",
  "process": {
    "pid": 284614,
    "tid": 284614,
    "ppid": 0,
    "uid": 1000,
    "euid": 1000,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 0,
    "cap_effective": 0,
    "secureexec": "",
    "filename": "bash",
    "binary_path": "/usr/bin/bash",
    "args": ""
  },
  "command": "export HISTFILESIZE=0 && cat /etc/passwd"
}
```
