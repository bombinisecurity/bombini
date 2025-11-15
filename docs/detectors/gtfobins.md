## GTFObins

GTFOBins detector detects [GTFOBins](https://gtfobins.github.io/) execution.
It checks if privileged shell is executed and returns process information about GTFOBins
binary that is spawning the shell.

### Required Linux Kernel Version

6.8 or greater

### Configuration

Config represents the list of GTFOBins filenames.

```yaml
enforce: true
gtfobins:    # https://gtfobins.github.io/#+shell%20+SUID%20+Sudo
  - aa-exec
  - awk
  - busctl
  - busybox
  - cabal
...
```

When enforce flag is set true execution of GTFOBins is blocked. False is by default.

### Event

The GTFOBins event is looks like:

```json
{
  "type": "GTFOBinsEvent",
  "process": {
    "start_time": "2025-05-31T10:04:07.027Z",
    "pid": 712851,
    "tid": 712851,
    "ppid": 462192,
    "uid": 1000,
    "euid": 0,
    "auid": 1000,
    "cap_inheritable": 0,
    "cap_permitted": 2199023255551,
    "cap_effective": 2199023255551,
    "secureexec": "SETUID | SETGID",
    "filename": "xargs",
    "binary_path": "/home/fedotoff/xargs",
    "args": "-a /dev/null sh -p",
    "container_id": ""
  },
  "timestamp": "2025-05-31T10:04:07.372Z",
}
```
