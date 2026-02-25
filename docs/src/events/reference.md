# Reference

JSON schema for all events.

## FileMon

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "FileEvent",
  "description": "File Event",
  "type": "object",
  "properties": {
    "hook": {
      "description": "LSM File hook info",
      "$ref": "#/$defs/LsmFileHook"
    },
    "parent": {
      "description": "Parent Information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process Information",
      "$ref": "#/$defs/Process"
    },
    "rule": {
      "description": "Rule name",
      "type": [
        "string",
        "null"
      ]
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "hook",
    "timestamp"
  ],
  "$defs": {
    "ChmodInfo": {
      "type": "object",
      "properties": {
        "i_mode": {
          "description": "i_mode",
          "type": "string"
        },
        "path": {
          "description": "full path",
          "type": "string"
        }
      },
      "required": [
        "path",
        "i_mode"
      ]
    },
    "ChownInfo": {
      "type": "object",
      "properties": {
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "path": {
          "description": "full path",
          "type": "string"
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "path",
        "uid",
        "gid"
      ]
    },
    "FileOpenInfo": {
      "type": "object",
      "properties": {
        "access_mode": {
          "description": "access mode passed to open()",
          "type": "string"
        },
        "creation_flags": {
          "description": "creation flags passed to open()",
          "type": "string"
        },
        "gid": {
          "description": "Group owner GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "i_mode": {
          "description": "i_mode",
          "type": "string"
        },
        "path": {
          "description": "full path",
          "type": "string"
        },
        "uid": {
          "description": "File owner UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "path",
        "access_mode",
        "creation_flags",
        "uid",
        "gid",
        "i_mode"
      ]
    },
    "IoctlInfo": {
      "type": "object",
      "properties": {
        "cmd": {
          "description": "cmd",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "i_mode": {
          "description": "i_mode",
          "type": "string"
        },
        "path": {
          "description": "full path",
          "type": "string"
        }
      },
      "required": [
        "path",
        "i_mode",
        "cmd"
      ]
    },
    "LsmFileHook": {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "FileOpen"
            }
          },
          "$ref": "#/$defs/FileOpenInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PathTruncate"
            }
          },
          "$ref": "#/$defs/PathInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PathUnlink"
            }
          },
          "$ref": "#/$defs/PathInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PathSymlink"
            }
          },
          "$ref": "#/$defs/PathSymlink",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PathChmod"
            }
          },
          "$ref": "#/$defs/ChmodInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PathChown"
            }
          },
          "$ref": "#/$defs/ChownInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "SbMount"
            }
          },
          "$ref": "#/$defs/MountInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "MmapFile"
            }
          },
          "$ref": "#/$defs/MmapInfo",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "FileIoctl"
            }
          },
          "$ref": "#/$defs/IoctlInfo",
          "required": [
            "type"
          ]
        }
      ]
    },
    "MmapInfo": {
      "type": "object",
      "properties": {
        "flags": {
          "description": "mmap flags",
          "type": "string"
        },
        "path": {
          "description": "full path",
          "type": "string"
        },
        "prot": {
          "description": "mmap protection",
          "type": "string"
        }
      },
      "required": [
        "path",
        "prot",
        "flags"
      ]
    },
    "MountInfo": {
      "type": "object",
      "properties": {
        "dev": {
          "description": "device name",
          "type": "string"
        },
        "flags": {
          "description": "mount flags",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "mnt": {
          "description": "mount path",
          "type": "string"
        }
      },
      "required": [
        "dev",
        "mnt",
        "flags"
      ]
    },
    "PathInfo": {
      "type": "object",
      "properties": {
        "path": {
          "description": "full path",
          "type": "string"
        }
      },
      "required": [
        "path"
      ]
    },
    "PathSymlink": {
      "type": "object",
      "properties": {
        "link_path": {
          "description": "full path",
          "type": "string"
        },
        "old_path": {
          "description": "symlink target",
          "type": "string"
        }
      },
      "required": [
        "link_path",
        "old_path"
      ]
    },
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
```

## GTFOBins

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GTFOBinsEvent",
  "description": "GTFO binary event execution attempt",
  "type": "object",
  "properties": {
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "timestamp"
  ],
  "$defs": {
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
```

## IOUringMon

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "IOUringEvent",
  "description": "io_uring events",
  "type": "object",
  "properties": {
    "op_info": {
      "description": "extra info for operation",
      "$ref": "#/$defs/IOUringOpInfo"
    },
    "opcode": {
      "description": "io_uring_ops",
      "type": "string"
    },
    "parent": {
      "description": "Parent process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "opcode",
    "op_info",
    "timestamp"
  ],
  "$defs": {
    "IOUringOpInfo": {
      "anyOf": [
        {
          "type": "object",
          "properties": {
            "access_flags": {
              "type": "string"
            },
            "creation_flags": {
              "type": "string"
            },
            "path": {
              "type": "string"
            }
          },
          "required": [
            "path",
            "access_flags",
            "creation_flags"
          ]
        },
        {
          "type": "object",
          "properties": {
            "path": {
              "type": "string"
            }
          },
          "required": [
            "path"
          ]
        },
        {
          "type": "object",
          "properties": {
            "path": {
              "type": "string"
            }
          },
          "required": [
            "path"
          ]
        },
        {
          "type": "object",
          "properties": {
            "addr": {
              "type": "string"
            },
            "port": {
              "type": "integer",
              "format": "uint16",
              "maximum": 65535,
              "minimum": 0
            }
          },
          "required": [
            "addr",
            "port"
          ]
        },
        {
          "type": "null"
        }
      ]
    },
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
```

## NetMon

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "NetworkEvent",
  "description": "Network event",
  "type": "object",
  "properties": {
    "network_event": {
      "description": "Network event",
      "$ref": "#/$defs/NetworkEventType"
    },
    "parent": {
      "description": "Parent process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "rule": {
      "description": "Rule name",
      "type": [
        "string",
        "null"
      ]
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "network_event",
    "timestamp"
  ],
  "$defs": {
    "NetworkEventType": {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "TcpConnectionEstablish"
            }
          },
          "$ref": "#/$defs/TcpConnection",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "TcpConnectionClose"
            }
          },
          "$ref": "#/$defs/TcpConnection",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "TcpConnectionAccept"
            }
          },
          "$ref": "#/$defs/TcpConnection",
          "required": [
            "type"
          ]
        }
      ]
    },
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    },
    "TcpConnection": {
      "description": "TCP IPv4 connection information",
      "type": "object",
      "properties": {
        "cookie": {
          "description": "socket cookie",
          "type": "integer",
          "format": "uint64",
          "minimum": 0
        },
        "daddr": {
          "description": "destination IP address,",
          "type": "string"
        },
        "dport": {
          "description": "destination port",
          "type": "integer",
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        },
        "saddr": {
          "description": "source IP address",
          "type": "string"
        },
        "sport": {
          "description": "source port",
          "type": "integer",
          "format": "uint16",
          "maximum": 65535,
          "minimum": 0
        }
      },
      "required": [
        "saddr",
        "daddr",
        "sport",
        "dport",
        "cookie"
      ]
    }
  }
}
```

## ProcMon

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ProcessExec",
  "description": "Process exec event",
  "type": "object",
  "properties": {
    "parent": {
      "description": "Parent Process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "timestamp"
  ],
  "$defs": {
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ProcessClone",
  "description": "Process clone event",
  "type": "object",
  "properties": {
    "parent": {
      "description": "Parent Process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "timestamp"
  ],
  "$defs": {
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ProcessExit",
  "description": "Process exit event",
  "type": "object",
  "properties": {
    "parent": {
      "description": "Parent Process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "timestamp"
  ],
  "$defs": {
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    }
  }
}
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ProcessEvent",
  "description": "Process Event",
  "type": "object",
  "properties": {
    "parent": {
      "description": "Parent process information",
      "anyOf": [
        {
          "$ref": "#/$defs/Process"
        },
        {
          "type": "null"
        }
      ]
    },
    "process": {
      "description": "Process information",
      "$ref": "#/$defs/Process"
    },
    "process_event": {
      "description": "Process event",
      "$ref": "#/$defs/ProcessEventType"
    },
    "rule": {
      "description": "Rule name",
      "type": [
        "string",
        "null"
      ]
    },
    "timestamp": {
      "description": "Event's date and time",
      "type": "string"
    }
  },
  "required": [
    "process",
    "process_event",
    "timestamp"
  ],
  "$defs": {
    "PrctlCmdUser": {
      "description": "Enumeration of prctl supported commands",
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "Opcode": {
              "type": "integer",
              "format": "uint8",
              "maximum": 255,
              "minimum": 0
            }
          },
          "additionalProperties": false,
          "required": [
            "Opcode"
          ]
        },
        {
          "type": "object",
          "properties": {
            "PrSetDumpable": {
              "type": "integer",
              "format": "uint8",
              "maximum": 255,
              "minimum": 0
            }
          },
          "additionalProperties": false,
          "required": [
            "PrSetDumpable"
          ]
        },
        {
          "type": "object",
          "properties": {
            "PrSetKeepCaps": {
              "type": "integer",
              "format": "uint8",
              "maximum": 255,
              "minimum": 0
            }
          },
          "additionalProperties": false,
          "required": [
            "PrSetKeepCaps"
          ]
        },
        {
          "type": "object",
          "properties": {
            "PrSetName": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                }
              },
              "required": [
                "name"
              ]
            }
          },
          "additionalProperties": false,
          "required": [
            "PrSetName"
          ]
        },
        {
          "type": "object",
          "properties": {
            "PrSetSecurebits": {
              "type": "integer",
              "format": "uint32",
              "minimum": 0
            }
          },
          "additionalProperties": false,
          "required": [
            "PrSetSecurebits"
          ]
        }
      ]
    },
    "Process": {
      "description": "Process information",
      "type": "object",
      "properties": {
        "args": {
          "description": "current work directory",
          "type": "string"
        },
        "auid": {
          "description": "login UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "binary_ima_hash": {
          "description": "IMA binary hash",
          "type": [
            "string",
            "null"
          ]
        },
        "binary_path": {
          "description": "full binary path",
          "type": "string"
        },
        "cap_effective": {
          "type": "string"
        },
        "cap_inheritable": {
          "type": "string"
        },
        "cap_permitted": {
          "type": "string"
        },
        "cloned": {
          "description": "is process cloned without exec",
          "type": "boolean"
        },
        "container_id": {
          "description": "skip for host",
          "type": [
            "string",
            "null"
          ]
        },
        "egid": {
          "description": "EGID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "euid": {
          "description": "EUID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "filename": {
          "description": "executable name",
          "type": "string"
        },
        "gid": {
          "description": "GID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "pid": {
          "description": "PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "ppid": {
          "description": "Parent PID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "secureexec": {
          "description": "SETUID, SETGID, FILECAPS, FILELESS_EXEC",
          "type": "string"
        },
        "start_time": {
          "description": "last exec or clone time",
          "type": "string"
        },
        "tid": {
          "description": "TID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "description": "UID",
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "start_time",
        "cloned",
        "pid",
        "tid",
        "ppid",
        "uid",
        "euid",
        "gid",
        "egid",
        "auid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "secureexec",
        "filename",
        "binary_path",
        "args"
      ]
    },
    "ProcessCapset": {
      "description": "Capset event",
      "type": "object",
      "properties": {
        "effective": {
          "type": "string"
        },
        "inheritable": {
          "type": "string"
        },
        "permitted": {
          "type": "string"
        }
      },
      "required": [
        "inheritable",
        "permitted",
        "effective"
      ]
    },
    "ProcessCreateUserNs": {
      "description": "CreateUserNs event",
      "type": "object"
    },
    "ProcessEventType": {
      "description": "Process event types",
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "Setuid"
            }
          },
          "$ref": "#/$defs/ProcessSetUid",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "Setgid"
            }
          },
          "$ref": "#/$defs/ProcessSetGid",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "Setcaps"
            }
          },
          "$ref": "#/$defs/ProcessCapset",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "Prctl"
            }
          },
          "$ref": "#/$defs/ProcessPrctl",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "CreateUserNs"
            }
          },
          "$ref": "#/$defs/ProcessCreateUserNs",
          "required": [
            "type"
          ]
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "PtraceAccessCheck"
            }
          },
          "$ref": "#/$defs/ProcessPtraceAccessCheck",
          "required": [
            "type"
          ]
        }
      ]
    },
    "ProcessPrctl": {
      "description": "Prctl event",
      "type": "object",
      "properties": {
        "cmd": {
          "$ref": "#/$defs/PrctlCmdUser"
        }
      },
      "required": [
        "cmd"
      ]
    },
    "ProcessPtraceAccessCheck": {
      "description": "PtraceAttach event",
      "type": "object",
      "properties": {
        "child": {
          "$ref": "#/$defs/Process"
        },
        "mode": {
          "type": "string"
        }
      },
      "required": [
        "child",
        "mode"
      ]
    },
    "ProcessSetGid": {
      "description": "Setgid event",
      "type": "object",
      "properties": {
        "egid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "flags": {
          "description": "LSM_SETID_* flag values",
          "type": "string"
        },
        "fsgid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "gid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "egid",
        "gid",
        "fsgid",
        "flags"
      ]
    },
    "ProcessSetUid": {
      "description": "Setuid event",
      "type": "object",
      "properties": {
        "euid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "flags": {
          "description": "LSM_SETID_* flag values",
          "type": "string"
        },
        "fsuid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        },
        "uid": {
          "type": "integer",
          "format": "uint32",
          "minimum": 0
        }
      },
      "required": [
        "euid",
        "uid",
        "fsuid",
        "flags"
      ]
    }
  }
}
```

