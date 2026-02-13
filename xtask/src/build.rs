use std::{env, path::PathBuf, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build_ebpf::{Architecture, Options as BuildOptions, build_ebpf},
    vmlinux_gen,
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
}

/// Build the project
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

fn check_vmlinux() -> Result<bool, anyhow::Error> {
    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") else {
        anyhow::bail!("CARGO_MANIFEST_DIR is not found")
    };
    let mut vmlinux_path = PathBuf::from(&manifest_dir);
    vmlinux_path.pop();
    vmlinux_path.push("bombini-detectors-ebpf/src/vmlinux.rs");
    Ok(vmlinux_path.exists())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    if !check_vmlinux()? {
        vmlinux_gen::vmlinux_gen(vmlinux_gen::Options {})?;
    }
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}
