use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{Architecture, Options as BuildOptions, build_ebpf};
use crate::util::get_musl_target;
use std::process::Command;

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Comma separated list of userspace cargo features
    #[clap(long, value_delimiter = ',')]
    pub features: Vec<String>,
}

/// Build the project
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let features = opts.features.join(",");
    let mut args = vec!["build"];
    if opts.release {
        let target = get_musl_target()?;
        args.extend(["--release", "--target", target]);
    }
    if !features.is_empty() {
        args.extend(["--features", features.as_str()]);
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}
