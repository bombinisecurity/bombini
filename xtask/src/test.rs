use std::process::{Command, Stdio};

use anyhow::Context as _;
use clap::Parser;

use procfs::sys::kernel::Version;

use crate::{
    build::{Options as BuildOptions, build},
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
    /// Print example events to stdout
    #[clap(long)]
    pub example_events: bool,
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
    if opts.example_events {
        args.push("--features=examples");
    }
    args.push("--");
    if opts.example_events {
        args.push("-q");
        args.push("--show-output");
    }
    args.push("--test-threads");
    args.push("1");

    let kernel_ver = Version::current().unwrap();
    let ver_6_2 = Version::new(6, 2, 0);
    let ver_6_8 = Version::new(6, 8, 0);
    let ver_6_14 = Version::new(6, 14, 0);

    if run_args.is_empty() && kernel_ver >= ver_6_2 {
        args.push("test_6_2_");
    }
    if run_args.is_empty() && kernel_ver >= ver_6_8 {
        args.push("test_6_8_");
    }
    if run_args.is_empty() && kernel_ver >= ver_6_14 {
        args.push("test_6_14_");
    }
    args.append(&mut run_args);

    let mut cargo = Command::new(args.first().expect("No first argument"));

    cargo.args(args.iter().skip(1));

    if opts.example_events {
        cargo.stdout(Stdio::piped());
    }
    let child = cargo.spawn().expect("failed to run the command");

    let output = child.wait_with_output().expect("Failed to wait");

    if !output.status.success() {
        anyhow::bail!("Failed to start tests `{}`", args.join(" "));
    }
    if opts.example_events {
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        for line in stdout_str.lines() {
            if !line.trim().is_empty()
                && let Ok(json_val) = serde_json::from_str::<serde_json::Value>(line)
                && let Ok(pretty) = serde_json::to_string_pretty(&json_val)
            {
                println!("{}", pretty);
            }
        }
    }
    Ok(())
}
