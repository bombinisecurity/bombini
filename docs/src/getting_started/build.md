# Build

First, install build dependencies:

1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Install `clang` and `libbpf-dev`. Ubuntu: `apt install clang libbpf-dev`.
3. Prepare environment for [Aya](https://aya-rs.dev/book/start/development/).

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

By default Bombini starts only `ProcMon` detector intercepting process execs and exits. To customize your Bombini setup, please, follow the [Configuration](../configuration/configuration.md).
Bombini uses `env_logger` crate. To see agent logs set `RUST_LOG=info|debug` environment variable.
