use std::process::Command;

use anyhow::Context as _;

/// Determine the host architecture and return the appropriate musl target
pub fn get_musl_target() -> Result<&'static str, anyhow::Error> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .context("failed to execute uname")?;

    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();

    match arch.as_str() {
        "arm64" | "aarch64" => Ok("aarch64-unknown-linux-musl"),
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        _ => Err(anyhow::anyhow!("Unsupported architecture: {}", arch)),
    }
}
