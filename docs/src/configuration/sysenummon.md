# SysEnumMon

> **Experimental.** This detector differs from the others: it correlates observations
> across a process tree rather than reporting single events. Correlation is currently tied
> to the direct parent, so processes spawned indirectly (`find -exec`, `bash -c`) may evade
> it, and the shared correlation state is read under RCU with time checks, so simultaneous
> hits on multiple CPUs can race. The behaviour and configuration may change once it gathers
> real-world feedback.

Detector correlates system enumeration (reconnaissance) activity. Automated privilege
escalation scanners (PEASS-ng: LinPEAS, LinEnum, pspy and similar) perform many small
enumeration steps in a short time: they execute information gathering binaries (`id`,
`whoami`, `uname`, `netstat` and so on) and read sensitive files (`/etc/shadow`,
`/etc/ssh/*` and so on). A single step is legitimate on its own, so an alert is raised only
when several distinct observations from the watch list accumulate inside one process tree
within a sliding time window.
Supported LSM hooks:

* `bprm_check_security` hook observes executed binary names on `execve`.
* `file_open` hook observes opened file paths.

Both hooks are always loaded, there is no per-hook enable switch. SysEnumMon depends on ProcMon.

## Required Linux Kernel Version

6.2 or greater

## Config Description

SysEnumMon does not provide rule-based filtering or sandbox mode. It is configured by a
watch list and two correlation parameters:

* `chain_size` - threshold `K`: number of distinct observations from the watch list that must occur within the window to raise an alert. `K` must not exceed 7, the per-process chain capacity.
* `window_size_sec` - sliding window length `W` in seconds. Only observations seen within the last `W` seconds are kept in a process tree's chain: as new observations arrive, any leading observation older than `W` seconds is dropped from the chain. An alert is raised when `K` distinct observations fall inside the same `W`-second window.
* `bprm_check.name` - list of binary names matched on `execve`.
* `file_open.path` - list of exact file paths matched on `file_open`.
* `file_open.path_prefix` - list of path prefixes matched on `file_open` (longest prefix match).

Observations are de-duplicated, so repeating the same entry does not advance the counter:
a script that calls `id` in a loop does not raise an alert. The total number of unique watch
list entries (names + paths + prefixes) must not exceed 256.

**Example**

```yaml
chain_size: 3
window_size_sec: 10
bprm_check:
  name:
    - id
    - whoami
    - uname
    - netstat
    - ss
    - getcap
file_open:
  path:
    - /etc/shadow
  path_prefix:
    - /etc/ssh
```
