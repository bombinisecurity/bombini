# Build

First, install build dependencies:

1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Prepare environment for [Aya](https://aya-rs.dev/book/start/development/).

Generate `vmlinux.rs` or skip this step if your kernel version is **6.8.0-86-generic**
(use `uname -a` to check kernel version).

```bash
cargo xtask vmlinux-gen
```
Release build:

```bash
cargo xtask build --release
```

## Run

```bash
sudo ./target/release/bombini --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config
```

Or using cargo:

```bash
cargo xtask run --release -- --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config
```

By default Bombini sends event to stdout in JSON format and starts only `ProcMon` detector intercepting
process execs and exits. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md).
Bombini uses `env_logger` crate. To see agent logs set `RUST_LOG=info|debug` environment variable. 

## Tarball

You can generate a tarball with installation scripts for bombini systemd service.
If you need config customization than update detector configs in `./config` directory and execute:

```bash
cargo xtask tarball --release
```

Release tarball will be located at `target/bombini.tar.gz`

### Install / Uninstall

Install bombini systemd service:

```bash
tar -xvf ./target/bombini.tar.gz -C ./target && \
sudo ./target/bombini/install.sh
```

Check events:

```bash
tail -f /var/log/bombini/bombini.log
```

Uninstall with uninstall.sh:

```bash
sudo ./target/bombini/uninstall.sh
```