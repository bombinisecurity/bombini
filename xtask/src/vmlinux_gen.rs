use std::{env, fs::File, path::PathBuf, process::Command};

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {}

pub fn vmlinux_gen(_opts: Options) -> Result<(), anyhow::Error> {
    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") else {
        anyhow::bail!("CARGO_MANIFEST_DIR is not found")
    };
    let mut vmlinux_path = PathBuf::from(&manifest_dir);
    vmlinux_path.pop();
    vmlinux_path.push("bombini-detectors-ebpf/src/vmlinux.rs");
    let vmlinux_file = File::create(vmlinux_path).unwrap();

    let _ = Command::new("aya-tool")
        .args(["generate", "task_struct"])
        .stdout(vmlinux_file.try_clone().unwrap())
        .status()
        .expect("can't start aya-tool");
    Ok(())
}
