FROM rust:latest

RUN apt update && apt install -y clang file

RUN curl -L https://github.com/libbpf/bpftool/releases/download/v7.6.0/bpftool-v7.6.0-amd64.tar.gz | tar xz -C /usr/bin/ && chmod +x /usr/bin/bpftool

RUN rustup toolchain install nightly --component cargo,clippy,rust-docs,rust-src,rust-std,rustc,rustfmt

RUN cargo install bpf-linker bindgen-cli
RUN cargo install --git https://github.com/aya-rs/aya -- aya-tool

WORKDIR /

RUN git clone https://github.com/bombinisecurity/bombini.git \
    && cd bombini \
    && cargo vendor --locked >> .cargo/config.toml
RUN cd bombini/bombini-detectors-ebpf && \
    cargo vendor --locked >> .cargo/config.toml
# Hack: vendor all rust-src deps
RUN cd /usr/local/rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/ \
    && mkdir .cargo && cargo +nightly vendor --locked  >> .cargo/config.toml \
    && cp -r ./vendor/* /bombini/bombini-detectors-ebpf/vendor/

ENTRYPOINT [ "/bin/bash" ]