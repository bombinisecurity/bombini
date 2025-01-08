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

It's inconvenient for now to launch, but if you really
want it to try, then, please, change in **config/config.yaml** **bpf_objs** path
to appropriate value and run the following command:

```bash
RUST_LOG=debug cargo xtask run -- --config-dir ./config
```
