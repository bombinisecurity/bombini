use std::env;
use std::fs;
use std::fs::File;
use std::path::PathBuf;

use flate2::Compression;
use flate2::write::GzEncoder;
use tar::Builder;

use anyhow::Context as _;
use clap::Parser;

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
}

/// Build and run the tests
pub fn tarball(opts: Options) -> Result<(), anyhow::Error> {
    // Build our ebpf program and the project
    build(BuildOptions {
        bpf_target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building project")?;

    // Create directories
    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") else {
        anyhow::bail!("CARGO_MANIFEST_DIR is not found")
    };
    let mut bombini_root_dir = PathBuf::from(&manifest_dir);
    bombini_root_dir.pop();
    let project_root = PathBuf::from(&bombini_root_dir);
    bombini_root_dir.push("target/bombini");
    if bombini_root_dir.exists() {
        let _ = fs::remove_dir_all(&bombini_root_dir);
    }
    let mut bombini_bin_dir = PathBuf::from(&bombini_root_dir);
    bombini_bin_dir.push("usr/local/bin");
    let mut bombini_lib_dir = PathBuf::from(&bombini_root_dir);
    bombini_lib_dir.push("usr/local/lib/bombini");
    let mut bombini_systemd = PathBuf::from(&bombini_root_dir);
    bombini_systemd.push("usr/lib/systemd/system");
    fs::create_dir_all(&bombini_bin_dir)?;
    let bombini_config_dir = bombini_lib_dir.as_path().join("config");
    let bombini_bpf_dir = bombini_lib_dir.as_path().join("bpf");
    fs::create_dir_all(&bombini_bpf_dir)?;
    fs::create_dir_all(&bombini_config_dir)?;
    fs::create_dir_all(&bombini_systemd)?;

    let mut target_dir = PathBuf::from(&project_root);
    target_dir = target_dir.join("target").join(opts.bpf_target.to_string());
    if opts.release {
        target_dir.push("release");
    } else {
        target_dir.push("debug");
    }
    for entry in fs::read_dir(project_root.as_path().join("config"))? {
        let config_path = entry?.path();
        fs::copy(
            &config_path,
            bombini_config_dir.join(config_path.file_name().unwrap()),
        )?;
    }
    for entry in fs::read_dir(target_dir)? {
        let path = entry?.path();
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        fs::copy(&path, bombini_bpf_dir.join(path.file_name().unwrap()))?;
    }
    target_dir = PathBuf::from(&project_root);
    target_dir.push("target");
    if opts.release {
        target_dir.push("release");
    } else {
        target_dir.push("debug");
    }
    fs::copy(target_dir.join("bombini"), bombini_bin_dir.join("bombini"))?;

    target_dir = PathBuf::from(&project_root);
    target_dir.push("install/tarball");

    fs::copy(
        target_dir.join("install.sh"),
        bombini_root_dir.join("install.sh"),
    )?;
    fs::copy(
        target_dir.join("uninstall.sh"),
        bombini_root_dir.join("uninstall.sh"),
    )?;
    fs::copy(
        target_dir.join("systemd").join("bombini.service"),
        bombini_systemd.join("bombini.service"),
    )?;

    let tar_gz = File::create(project_root.join("target").join("bombini.tar.gz"))?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut builder = Builder::new(enc);
    builder.append_dir_all("./bombini", &bombini_root_dir)?;
    builder.into_inner()?.finish()?;

    fs::remove_dir_all(bombini_root_dir)?;
    Ok(())
}
