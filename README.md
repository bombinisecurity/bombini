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

```bash
cargo xtask build
```

## Run

You can try bombini agent this way:

```bash
RUST_LOG=debug cargo xtask run -- --bpf-objs ./target/bpfel-unknown-none/debug --config-dir ./config --stdout
```

Also you can use file as output or unix socket combining with
[vector](https://github.com/vectordotdev/vector).

### File

Start vector agent:

```bash
vector --config ./vector/vector-file.yaml
```

Start bombini with events redirecting to file:

```bash
RUST_LOG=debug cargo xtask run -- --bpf-objs ./target/bpfel-unknown-none/debug --config-dir ./config --event-log ./bombini.log
```

### Unix socket

Start vector agent with unix socket listner:

```bash
vector --config ./vector/vector-sock.yaml
```

Start bombini with events redirecting to unix socket:

```bash
RUST_LOG=debug cargo xtask run -- --bpf-objs ./target/bpfel-unknown-none/debug --config-dir ./config --event-socket /tmp/bombini.sock
```
