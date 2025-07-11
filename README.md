# bombini

Bombini is an eBPF-based agent for security monitoring. It is build on a
top of [Aya](https://github.com/aya-rs/aya) library. Design concepts can be
found [here](docs/design.md).

## Run

Your Linux kernel version must be greater or equal **5.15**.
[Compatibility](https://github.com/aya-rs/aya/issues/349) between different kernel versions (CO-RE) is not yet fully implemented.

The easiest way to use Bombini is to build docker image and run:

```bash
docker build  -t bombini .
```

Before run, check if LSM BPF is enabled on your system.

```
cat /sys/kernel/security/lsm
```

if there is `bpf` in the output, than BPF LSM is enabled.
Otherwise, you have to enable it adding this line to `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX="lsm=[previos lsm modules],bpf"
```

Update grub and reboot the system.

Prepare configuration files and enable detectors for your needs. You can copy `./config` directory and modify config files.
`config.yaml` has global Bombini parameters and enumerates detectors to be loaded. Other config files provides parameters for corresponding detector.
To know more about detectors look at [docs](docs/detectors/).

Run bombini:

```bash
docker run --pid=host --rm -it --privileged --env "RUST_LOG=info" -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf bombini
```

You can also use file as output or unix socket combining with
[vector](https://github.com/vectordotdev/vector).

### File
```bash
touch /tmp/bombini.log
docker run --pid=host --rm -it --privileged --env "RUST_LOG=info" -v <your-config-dir>:/usr/local/lib/bombini/config:ro -v /tmp/bombini.log:/log/bombini.log -v /sys/fs/bpf:/sys/fs/bpf bombini --event-log /log/bombini.log
```

### Unix socket
```bash
vector --config ./vector/vector-sock.yaml
docker run --pid=host --rm -it --privileged --env "RUST_LOG=info" -v <your-config-dir>:/usr/local/lib/bombini/config:ro -v /tmp/bombini.sock:/log/bombini.sock -v /sys/fs/bpf:/sys/fs/bpf bombini --event-socket /log/bombini.sock
```

## Build

1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Prepare environment for [Aya](https://aya-rs.dev/book/start/development/).

If you building Bombini on Linux kernel with version **6.8.0-62-generic**, you can skip the next step.
Otherwise, please, regenerate `vmlinux.rs` before building:

```bash
./bombini-detectors-ebpf/generate_vmlinux.sh
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

You can run bombini this way:

```bash
RUST_LOG=info sudo -E ./target/release/bombini --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --stdout
```

Or using cargo:

```bash
RUST_LOG=info cargo xtask run --release -- --bpf-objs ./target/bpfel-unknown-none/release --config-dir ./config --stdout
```