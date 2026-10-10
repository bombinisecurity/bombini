//! `bombini --validate`: check detector configs without root or eBPF loading
//!
//! The rule parser, optimizer and serializer all live in user space, so rules
//! can be checked on any machine:
//!
//! - `bombini --validate` checks the detectors enabled in `--config-dir`
//! - `bombini --validate <config-dir|file.yaml>` checks the given path

use clap::{ArgMatches, FromArgMatches, parser::ValueSource};

use std::path::{Path, PathBuf};

use crate::{config::parse_detector_config, options::Options};

/// Entry point for `bombini --validate [PATH]`
pub fn run(matches: &ArgMatches) -> Result<(), anyhow::Error> {
    let args = Options::from_arg_matches(matches)?;
    let files = match args.validate {
        Some(Some(path)) => {
            // The path replaces the config dir, so its options would be ignored
            if args.detectors.is_some()
                || matches.value_source("config_dir") == Some(ValueSource::CommandLine)
            {
                anyhow::bail!("--detector and --config-dir cannot be used with a --validate path");
            }
            path_configs(Path::new(&path))?
        }
        _ => enabled_configs()?,
    };
    check_files(files)
}

/// Detector configs that the agent loads from `--config-dir`
fn enabled_configs() -> Result<Vec<(String, PathBuf)>, anyhow::Error> {
    let mut options = Options::default();
    options.parse_options()?;
    let mut names = options.detectors.unwrap_or_default();
    // procmon is always loaded, see Config::parse_configs
    if !names.iter().any(|name| name == "procmon") {
        names.push("procmon".to_string());
    }
    let dir = PathBuf::from(&options.config_dir);
    Ok(names
        .into_iter()
        .map(|name| {
            let file = dir.join(format!("{name}.yaml"));
            (name, file)
        })
        .collect())
}

/// Detector name and path pairs for a config dir or a single .yaml file
fn path_configs(path: &Path) -> Result<Vec<(String, PathBuf)>, anyhow::Error> {
    let files = if path.is_dir() {
        // A config dir holds configs of different detectors, named <detector>.yaml
        std::fs::read_dir(path)?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let name = path.file_stem()?.to_string_lossy().into_owned();
                let detector = name.split('-').next().unwrap().to_string();
                (path.extension()? == "yaml" && name != "config").then_some((detector, path))
            })
            .collect::<Vec<_>>()
    } else if path.is_file() && path.extension().is_some_and(|ext| ext == "yaml") {
        // A single file: the detector name is taken from the file name
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let detector = name.split('-').next().unwrap();
        vec![(detector.to_string(), path.to_path_buf())]
    } else {
        anyhow::bail!("{}: not a directory or a .yaml file", path.display());
    };

    if files.is_empty() {
        anyhow::bail!("{}: no detector configs found", path.display());
    }
    Ok(files)
}

/// Check every config and report each result, failing if any check failed
fn check_files(files: Vec<(String, PathBuf)>) -> Result<(), anyhow::Error> {
    let mut failed = false;
    for (name, file) in files {
        match check_file(&name, &file) {
            Ok(()) => println!("{}: ok", file.display()),
            Err(e) => {
                failed = true;
                eprintln!("{}: {e:#}", file.display());
            }
        }
    }
    if failed {
        anyhow::bail!("validation failed");
    }
    Ok(())
}

/// Parse a single detector config and compile its rules
fn check_file(name: &str, file: &Path) -> Result<(), anyhow::Error> {
    let yaml = std::fs::read_to_string(file)?;
    parse_detector_config(name, &yaml)?
        .check_rules()
        .map_err(|e| anyhow::anyhow!("{name}: {e:#}"))
}
