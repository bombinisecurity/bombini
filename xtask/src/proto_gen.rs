use std::{env, path::PathBuf};

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {}

pub fn proto_gen(_opts: Options) -> Result<(), anyhow::Error> {
    let proto_inculdes = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let proto_config = proto_inculdes.join("config.proto");
    let out_dir = proto_inculdes.join("../bombini/src/proto");
    prost_build::Config::new()
        .out_dir(&out_dir)
        .type_attribute(".", "#[derive(serde::Deserialize)]")
        .type_attribute("config.ProcessFilter", "#[serde(default)]")
        .type_attribute("config.IpFilter", "#[serde(default)]")
        .type_attribute("config.PathFilter", "#[serde(default)]")
        .compile_protos(&[proto_config], &[proto_inculdes])?;
    Ok(())
}
