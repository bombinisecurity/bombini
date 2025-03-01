use std::env;

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::{thread, time::Duration};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use tempfile::tempfile;

static EXE_BOMBINI: &str = env!("CARGO_BIN_EXE_bombini");
static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");
#[test]
fn test_detectors_load() {
    let mut project_dir = PathBuf::from(PROJECT_DIR);
    project_dir.pop();
    let mut config = project_dir.clone();
    config.push("config");
    let mut bpf_objs = project_dir.clone();
    bpf_objs.push("target/bpfel-unknown-none");
    if EXE_BOMBINI.contains("release") {
        bpf_objs.push("release");
    } else {
        bpf_objs.push("debug");
    }

    let mut bombini_log = tempfile().expect("Unable to create temp dir");

    let bombini = Command::new(EXE_BOMBINI)
        .args([
            "--config-dir",
            config.to_str().unwrap(),
            "--bpf-objs",
            bpf_objs.to_str().unwrap(),
            "--stdout",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();
    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    let mut log = String::new();
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(1500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGTERM);

    bombini_log.seek(SeekFrom::Start(0)).unwrap();

    let _ = bombini.wait().unwrap();

    bombini_log.read_to_string(&mut log).unwrap();

    // Check loaded detectors
    assert!(log.contains("gtfobins is loaded"));
    assert!(log.contains("procmon is loaded"));
    assert!(log.contains("histfile is loaded"));
}

#[test]
#[ignore]
fn test_gtfobins_detector_file() {}

#[test]
#[ignore]
fn test_procmon_file() {}

#[test]
#[ignore]
fn test_hist_file() {}
