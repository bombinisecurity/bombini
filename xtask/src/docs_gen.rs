use clap::Parser;
use std::{env, fs::OpenOptions, io::Write, path::PathBuf, process::Command};

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
    // Generate json schema for all events
    let event_ref =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/events/reference.md");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&event_ref)
        .unwrap();
    let _ = writeln!(file, "# Reference\n\nJSON schema for all events.\n");
    let _ = Command::new("cargo")
        .args([
            "test",
            "--features=schema",
            "--",
            "--test-threads",
            "1",
            "generate_",
        ])
        .status()?;

    Ok(())
}
