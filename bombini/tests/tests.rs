use std::{env, fs};

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use tempfile::{tempfile, Builder};

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

    let mut bombini_log = tempfile().expect("Unable to create temp log file");

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

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

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
fn test_procmon_file() {
    let mut project_dir = PathBuf::from(PROJECT_DIR);
    project_dir.pop();
    let mut config = project_dir.clone();
    config.push("config/config.yaml");
    let mut bpf_objs = project_dir.clone();
    bpf_objs.push("target/bpfel-unknown-none");
    if EXE_BOMBINI.contains("release") {
        bpf_objs.push("release");
    } else {
        bpf_objs.push("debug");
    }

    let temp_dir = Builder::new()
        .prefix("bombini-test-")
        .rand_bytes(5)
        .keep(true)
        .tempdir()
        .expect("can't create temp dir");

    let bomini_temp_dir = temp_dir.path();
    let mut tmp_config = bomini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bomini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    let bombini_log =
        File::create(bomini_temp_dir.join("bombini.log")).expect("can't create log file");
    let _ = fs::write(tmp_config.join("procmon.yaml"), "expose-events: true");
    let event_log = temp_dir.path().join("events.log");

    let bombini = Command::new(EXE_BOMBINI)
        .args([
            "--config-dir",
            tmp_config.to_str().unwrap(),
            "--bpf-objs",
            bpf_objs.to_str().unwrap(),
            "--event-log",
            event_log.to_str().unwrap(),
            "--detector",
            "procmon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(1500));

    let _ = Command::new("ls")
        .args(["-lah"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start ls");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(1000));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);

    let _ = fs::remove_dir(bomini_temp_dir);
}

#[test]
#[ignore]
fn test_hist_file() {}
