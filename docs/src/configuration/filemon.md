# FileMon

Detector provides events related to file / filesystem operations.
Supported LSM hooks:

* `file_open` hook  provides info about file owner/permissions + permissions with process accessed the file.
* `mmap_file` hook provides info about mmaped file: path, protection flags.
* `path_truncate` hook provides info about path truncated by truncate syscall.
* `path_unlink` provides info about path being deleted.
* `path_symlink` provides info about symlink creation.
* `path_chmod` provides info about changing file permissions.
* `path_chown` provides info about changing file owner.
* `sb_mount` provides info about mounted devices.
* `file_ioctl` provides info about ioctl commands.

## Required Linux Kernel Version

* `file_open`: 6.2 or greater
* `mmap_file`: 6.2 or greater
* `sb_mount`: 6.2 or greater
* `file_ioctl`: 6.2 or greater
* `path_truncate`: 6.8 or greater
* `path_unlink`: 6.8 or greater
* `path_symlink`: 6.8 or greater
* `path_chmod`: 6.8 or greater
* `path_chown`: 6.8 or greater

## Config Description

Config represents a dictionary with supported LSM BPF file hooks:

* file_open
* mmap_file
* path_truncate
* path_unlink
* path_symlink
* path_chmod
* path_chown
* sb_mount
* file_ioctl

For each file hook the following options are supported:

* `enabled` enables detection for current hook. False by default.

### Event filtering

FileMon detector supports [process filtering](filtering.md#process-filter).

FileMon also supports [path filtering](filtering.md/#path-filter) for hooks:

* file_open
* path_truncate
* path_unlink
* path_symlink
* path_chmod
* path_chown
* mmap_file
* file_ioctl

Path filtering for the symlink hook is based on the target path, not the symlink file.

Config example:

```yaml
file_open:
  enabled: true
  path_filter:
    name:
      - .history
      - .bash_history
    prefix:
      - /boot
    path:
      - /etc/passwd
mmap_file:
  enabled: true
path_truncate:
  enabled: false
path_unlink:
  enabled: false
path_symlink:
  enabled: false
path_chmod:
  enabled: false
path_chown:
  enabled: false
sb_mount:
  enabled: false
process_filter:
  binary:
    name:
      - tail
    path:
      - /usr/bin/cat
```
