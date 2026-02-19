use std::{env, path::PathBuf, process::Command};

use clap::Parser;

use crate::vmlinux_gen;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
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

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    if !check_vmlinux()? {
        vmlinux_gen::vmlinux_gen(vmlinux_gen::Options {})?;
    }
    let dir = PathBuf::from("bombini-detectors-ebpf");
    let target = format!("--target={}", opts.target);
    let mut args = vec!["build", target.as_str(), "-Z", "build-std=core"];
    if opts.release {
        args.push("--release")
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
