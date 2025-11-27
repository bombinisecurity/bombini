use std::process::Command;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {}

pub fn docs_gen(_opts: Options) -> Result<(), anyhow::Error> {
    let _ = Command::new("protoc")
        .args([
            "--doc_out=./docs/src/configuration",
            "--doc_opt=markdown,reference.md",
            "proto/config.proto",
        ])
        .status()?;
    Ok(())
}
