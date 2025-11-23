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
