## Overview

Let's look at some design concepts.

### Detector

Detector provides a common interface for loading eBPF programs, initializing
maps and attaching programs to hook points. All detector programs are viewed
externally as a single entity that delivers events. EBPF part of detectors is
located
[here](https://github.com/anfedotoff/bombini/tree/main/bombini-detectors-ebpf/src/bin).
User mode part is
[here](https://github.com/anfedotoff/bombini/tree/main/bombini/src/detector). Detectors
also can provide information not only for user but for other detectors storing it
in maps. Some parts of the detectors can be reused across different detectors.
Detectors submit events to user space using ring buffer. Detectors use YAML
config files for initialization.

### Monitor

Monitor observes new low level events (messages) and extracts them from ring buffer.

### Transmuter

Transmuter converts (transmutes) low kernel event into serializable (json, for
example) data structure. It also can enrich kernel event with some user mode
data.

### Transmitter

Transmitter sends serialized events (byte arrays) to different sources (unix socket, stdout, file, etc).

### Config

Config holds global agent configuration. It also have list of the detectors to
load during start up.

### Registry

Registry stores loaded detectors. It can load/unload detectors and possibly
interact with them (change config maps).

## List of the Detectors

## GTFObins

GTFOBins detector tries to detect [GTFOBins](https://gtfobins.github.io/) execution.
It checks if privileged binary is executed and returns the binary name with
command line args as an event. List of GTFOBins is provided in YAML config.

## HistFile

HistFile detector's goal is to detect cases when user stops writing bash
history to `~/.bash_history`. It can be done using this commands:

```bash
export HISTFILESIZE=0
export HISTSIZE=0
```

Detector attaches to `/bin/bash` `readline` func with uretprobe and uses **lpm_trie**
map to check for commands above.
