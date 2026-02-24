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

## Event Filtering

The following list of hooks support event filtering by rules:

* file_open
* path_truncate
* path_unlink
* path_symlink
* path_chmod
* path_chown
* mmap_file
* file_ioctl

### file_open

`file_open` supports the following filtering attributes:

* `path` - the absolute path of opening file.
* `path_prefix` - the absolute path prefix of opening file.
* `name` - the name of opening file.

**Example**

```yaml
file_open:
  enabled: true
  rules:
  - rule: OpenTestRule
    scope: binary_name in ["ls", "tail"]
    event: path in ["/etc"] OR name == "filemon.yaml"
```

### path_truncate

`file_truncate` supports the following filtering attributes:

* `path` - the absolute path of truncating file.
* `path_prefix` - the absolute path prefix of truncating file.
* `name` - the name of truncating file.

**Example**

```yaml
path_truncate:
  enabled: true
  rules:
  - rule: TruncateTestRule
    event: path_prefix == "/tmp/bombini-test-"
```

### path_unlink

`path_unlink` supports the following filtering attributes:

* `path` - the absolute path of deleting file.
* `path_prefix` - the absolute path prefix of deleting file.
* `name` - the name of deleting file.

**Example**

```yaml
path_unlink:
  enabled: true
  rules:
  - rule: UnlinkTestRule
    event: path_prefix == "/tmp" AND name == "test.json"
```

### path_symlink

`path_symlink` supports the following filtering attributes:

* `path` - the path of target file (maybe relative).
* `path_prefix` - the path prefix of target file (maybe relative).

**Example**

```yaml
path_symlink:
  enabled: true
  rules:
  - rule: SymlinkTestRule
    event: path_prefix == "../"
```

### path_chmod

`path_chmod` supports the following filtering attributes:

* `path` - the absolute path of changing permissions file.
* `path_prefix` - the absolute path prefix of changing permissions file.
* `name` - the name of changing permissions file.
* `mode` - the new file's permissions.

**Example**

```yaml
path_chmod:
  enabled: true
  rules:
  - rule: ChmodTestRule
    event: name == "filemon.yaml" AND mode in ["S_IWOTH","S_IWGRP","S_IWUSR"]
```

### path_chown

`path_chown` supports the following filtering attributes:

* `path` - the absolute path of changing owner file.
* `path_prefix` - the absolute path prefix of changing owner file.
* `name` - the name of changing owner file.
* `uid` - the new file's owner UID.
* `gid` - the new file's owner GID.

**Example**

```yaml
path_chown:
  enabled: true
  rules:
  - rule: ChownTestRule
    event: name == "filemon.yaml" AND uid == 0 AND gid == 0
```

### mmap_file

`mmap_file` supports the following filtering attributes:

* `path` - the absolute path of mmaped file.
* `path_prefix` - the absolute path prefix of mmaped file.
* `name` - the name of mmaped file.

**Example**

```yaml
mmap_file:
  enabled: true
  rules:
  - rule: MmapTestRule
    event: name == "filemon.yaml"
```

### file_ioctl

`file_ioctl` supports the following filtering attributes:

* `path` - the absolute path of device file.
* `path_prefix` - the absolute path prefix of device file.
* `name` - the name of device file.
* `cmd` - ioctl command.

**Example**

```yaml
file_ioctl:
  enabled: true
  rules:
  - rule: IoctlTestRule
    event: path_prefix == "/dev" AND cmd in [4712, 2147766906, 769]
```