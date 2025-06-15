# bombini

Bombini is an eBPF-based agent for (mostly) security monitoring. Bombini
provides components for fast prototyping eBPF detectors. Not all components are
implemented yet and it's more like proof of concept for now. It is build on a
top of [Aya](https://github.com/aya-rs/aya) library. Design concepts can be
found [here](docs/design.md).

## Prerequisites

1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Prepare environment for [Aya](https://aya-rs.dev/book/start/development/).

## Build

[Compatibility](https://github.com/aya-rs/aya/issues/349) between different kernel versions (CO-RE) is not yet fully implemented.
If you building Bombini on **Ubuntu 24 with Linux kernel 6.8**, you can skip the next step.
Otherwise, please, regenerate `vmlinux.rs` before building:

```bash
cd bombini-detectors-ebpf && ./generate_vmlinux.sh && cd ../
```
Release build:

```bash
cargo xtask build --relese
```
You can generate a tarball with instalation scripts for bombini systemd service:

```bash
cargo xtask tarball --relese
```

Release tarball will be located at `target/bombini.tar.gz`

## Run

First, check if LSM BPF is enabled on your system.

```
cat /sys/kernel/security/lsm
```

if there is `bpf` in the output, than BPF LSM is enabled.
Otherwise, you have to enable it adding this line to `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX="lsm=[previos lsm modules],bpf"
```

Update grub and reboot the system.


You can run bombini this way:

```bash
RUST_LOG=info sudo -E ./target/release/bombini --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --stdout
```

Or using cargo:

```bash
RUST_LOG=info cargo xtask run --release -- --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --stdout
```

Also you can use file as output or unix socket combining with
[vector](https://github.com/vectordotdev/vector).

### File

Start vector agent:

```bash
mkdir /tmp/vector && vector --config ./vector/vector-file.yaml
```

Start bombini with events redirecting to file:

```bash
RUST_LOG=info cargo xtask run --release -- --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --event-log ./bombini.log
```

### Unix socket

Start vector agent with unix socket listner:

```bash
vector --config ./vector/vector-sock.yaml
```

Start bombini with events redirecting to unix socket:

```bash
RUST_LOG=info cargo xtask run --release -- --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --event-socket /tmp/bombini.sock
```
