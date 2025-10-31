## HistFile

HistFile detector detects cases when user stops writing bash
history to `~/.bash_history`. It can be done using this commands:

```bash
export HISTFILESIZE=0
export HISTSIZE=0
```

Detector attaches to `/bin/bash` `readline` func with uretprobe and uses **lpm_trie**
map to check for commands above.

**NOTE**

1. Be sure that Bombini is started before `/bin/bash` process.
2. If you use Bombini container mount `/bin/bash` inside the container.

```bash
docker run --pid=host --rm -it --privileged --env "RUST_LOG=info" -v <your-config-dir>:/usr/local/lib/bombini/config:ro -v /bin/bash:/bin/bash:ro -v /sys/fs/bpf:/sys/fs/bpf bombini
```

### Required Linux Kernel Version

5.15 or greater

### Config

This detector has no config

### Event

```json
{
  "type": "HistFileEvent",
  "process": {
    "start_time": "2025-05-31T10:05:01.032Z",
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
    "container_id": ""
  },
  "command": "export HISTFILESIZE=0 && cat /etc/passwd",
  "timestamp": "2025-05-31T10:05:01.173Z"
}
```
