use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build::{build, Options as BuildOptions},
    build_ebpf::Architecture,
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Just build do not run
    #[clap(long)]
    pub no_run: bool,
    /// The command used to wrap cargo
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to cargo test
    #[clap(name = "args", last = true)]
    pub test_args: Vec<String>,
}

/// Build and run the tests
pub fn test(opts: Options) -> Result<(), anyhow::Error> {
    // Build our ebpf program and the project
    build(BuildOptions {
        bpf_target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building project")?;

    // arguments to pass cargo test
    let mut run_args: Vec<_> = opts.test_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    let cargo_path = which::which("cargo")?;
    args.push(cargo_path.to_str().unwrap());
    args.push("test");
    if opts.release {
        args.push("--release");
    }
    if opts.no_run {
        args.push("--no-run");
    }
    args.push("--");
    args.push("--test-threads");
    args.push("1");
    args.append(&mut run_args);

    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    assert!(status.success());
    if !status.success() {
        anyhow::bail!("Failed to start tests `{}`", args.join(" "));
    }
    Ok(())
}
