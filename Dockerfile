FROM rust:latest AS bombini-builder
RUN apt update && apt install -y  bpftool clang
# Aya Development Environment https://aya-rs.dev/book/start/development/
RUN rustup install stable; \
    rustup toolchain install nightly --component rust-src; \
    cargo install bpf-linker bindgen-cli; \
    cargo install --git https://github.com/aya-rs/aya -- aya-tool;
COPY . ./
# Update vmlinux.rs acroding current kernel verison
RUN  uname -a; \
    ./bombini-detectors-ebpf/generate_vmlinux.sh
RUN cargo xtask build --release
RUN mkdir -p ./target/bpf-objs && \
    find ./target/bpfel-unknown-none/release -maxdepth 1 -exec file {} + | \
    grep -i elf | \
    awk -F: '{print $1}' | \
    xargs -I {} cp {} ./target/bpf-objs/

FROM gcr.io/distroless/cc-debian12
COPY --from=bombini-builder ./target/release/bombini /usr/local/bin/
COPY --from=bombini-builder ./target/bpf-objs /usr/local/lib/bombini/bpf
COPY --from=bombini-builder ./config /usr/local/lib/bombini/config

ENTRYPOINT [ "/usr/local/bin/bombini" ]

# How to run:
# docker run --pid=host --rm -it --privileged --env "RUST_LOG=info" -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf bombini
