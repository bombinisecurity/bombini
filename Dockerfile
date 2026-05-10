FROM rust:1.95.0 AS bombini-builder

RUN apt update && apt install -y  bpftool clang libbpf-dev
WORKDIR /bombini
COPY . ./
RUN rustup show && cargo install bpf-linker bindgen-cli
RUN cargo xtask build --release
RUN mkdir -p ./target/bpf-objs && \
    find ./target/bpfel-unknown-none/release -maxdepth 1 -exec file {} + | \
    grep -i elf | \
    awk -F: '{print $1}' | \
    xargs -I {} cp {} ./target/bpf-objs/

FROM gcr.io/distroless/cc-debian12
COPY --from=bombini-builder /bombini/target/x86_64-unknown-linux-musl/release/bombini /usr/local/bin/
COPY --from=bombini-builder /bombini/target/bpf-objs /usr/local/lib/bombini/bpf
COPY --from=bombini-builder /bombini/config /usr/local/lib/bombini/config

ENTRYPOINT [ "/usr/local/bin/bombini" ]

# How to run
LABEL description="docker run --pid=host --rm -it --privileged --env 'RUST_LOG=info' -v <your-config-dir>:/usr/local/lib/bombini/config:ro  -v /sys/fs/bpf:/sys/fs/bpf bombini"
