use std::{env, path::PathBuf};

use clap::Parser;
use lalrpop::Configuration;

#[derive(Debug, Parser)]
pub struct Options {}

pub fn rule_parser_gen(_opts: Options) -> Result<(), anyhow::Error> {
    let rule_inculdes = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bombini/src/rule");
    Configuration::new()
        .set_in_dir(rule_inculdes.clone())
        .set_out_dir(rule_inculdes)
        .process()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}
