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

### Transmiter (not implemented yet)

Transmiter sends event to different sources (network, stdout, file).

### Config

Config holds global agent configuration. It also have list of the detectors to
load during start up.

### Registry

Registry stores loaded detectors. It can load/unload detectors and possibly
interact with them (change config maps).

## Examples of Detectors

## Simple

Simple detector is just for testing this design concept. It attaches to kprobe
**security_bprm_check** gets provided uid, compares this uid with current uid in
bpf part and sends the event with current pid.

## GTFObins

GTFOBins detector tries to detect [GTFOBins](https://gtfobins.github.io/) execution.
It checks if privileged binary is executed and returns the binary name with
command line args as an event. List of GTFOBins is provided in YAML config.
