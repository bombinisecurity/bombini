FROM rust:1.95.0 AS bombini-builder

# musl-tools: ring, the rustls crypto provider, compiles C for musl
RUN apt update && apt install -y  bpftool clang libbpf-dev musl-tools
WORKDIR /bombini
COPY . ./
RUN rustup show && cargo install bindgen-cli
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
&& cargo binstall -y bpf-linker
# The image is meant for kubernetes, so pod enrichment is compiled in
RUN cargo xtask build --release --features k8s
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
