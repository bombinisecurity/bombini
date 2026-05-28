# Introduction

<img align="right" src="./img/bombini_logo.png" alt="Bombini logo" width="256" style="height: auto;">

**Bombini** is an eBPF-based security agent written entirely in Rust using the [Aya](https://github.com/aya-rs/aya) library and built on LSM (Linux Security Module) BPF hooks. At its core, Bombini employs modular components called Detectors, each responsible for monitoring and reporting specific types of system events.

Detectors are organized by event class and kernel subsystem:

* *ProcMon*: Tracks process creation and termination, as well as privilege escalation events.
* *FileMon*: Monitors file system activity and file-related operations.
* *NetMon*: Observes TCP connection establishment and teardown.
* *KernelMon*: Detects interaction with eBPF kernel subsystem.
* *IOUringMon*: Inspects io_uring submission queue activity.


All Detectors perform in-kernel event filtering directly within eBPF programs, minimizing overhead and reducing the volume of data sent to userspace.

Bombini rule engine enables the detection of advanced threats, such as the disclosure of [GTFOBins](https://gtfobins.github.io/), which involves the execution of privileged shells through the abuse of eligible binaries.

Additionally, *ProcMon*, *FileMon* and *NetMon* can optionally enforce sandboxing policies, allowing fine-grained control over process execution, file access and ip connections based on configurable rules.

By combining the safety of Rust, the power of eBPF, and the flexibility of LSM hooks, Bombini provides a lightweight, high-performance, and extensible runtime security monitoring solution for Linux systems.
