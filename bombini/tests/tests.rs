use std::fs;

use std::fs::File;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use procfs::sys::kernel::Version;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;

mod common;

use common::*;

#[test]
fn test_6_2_detectors_load() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    config.pop();

    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");

    let kernel_ver = Version::current().unwrap();
    let ver_6_8 = Version::new(6, 8, 0);
    let mut args = vec![
        "--config-dir",
        config.to_str().unwrap(),
        "--bpf-objs",
        bpf_objs.to_str().unwrap(),
        "--detector",
        "procmon",
        "--detector",
        "filemon",
        "--detector",
        "netmon",
    ];
    if kernel_ver >= ver_6_8 {
        let mut detectors_6_8 = vec!["--detector", "io_uringmon", "--detector", "gtfobins"];
        args.append(&mut detectors_6_8);
    }
    let bombini = Command::new(EXE_BOMBINI)
        .args(&args)
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .stdout(Stdio::null())
        .spawn();
    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(4000));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let log = fs::read_to_string(bombini_temp_dir.join("bombini.log")).expect("can't read events");

    // Check loaded detectors
    assert!(log.contains("procmon is loaded"));
    assert!(log.contains("filemon is loaded"));
    assert!(log.contains("netmon is loaded"));
    if kernel_ver >= ver_6_8 {
        assert!(log.contains("gtfobins is loaded"));
        assert!(log.contains("io_uringmon is loaded"));
    }

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_gtfobins_detector() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let _ = fs::copy(
        config.join("gtfobins.yaml"),
        tmp_config.join("gtfobins.yaml"),
    );
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
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
            "--detector",
            "gtfobins",
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

    let mut gtfo_proc = Command::new("sudo")
        .args(["xargs", "-a", "/dev/null", "sh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start ls");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(gtfo_proc.id() as i32), Signal::SIGKILL);

    let _ = gtfo_proc.wait().unwrap();

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"GTFOBinsEvent\"").count(), 1);
    assert_eq!(events.matches("\"filename\":\"xargs\"").count(), 7);
    assert_eq!(events.matches("\"args\":\"-a /dev/null sh\"").count(), 7);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_io_uringmon() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let _ = fs::File::create(tmp_config.join("io_uringmon.yaml"));
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
            "--detector",
            "io_uringmon",
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

    let _ = Command::new("nslookup")
        .args(["google.com"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start nslookup");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"filename\":\"nslookup\"").count(), 2);
    ma::assert_ge!(events.matches("\"args\":\"google.com\"").count(), 2);
    ma::assert_ge!(events.matches("\"type\":\"IOUringEvent\"").count(), 1);
    ma::assert_ge!(
        events.matches("\"opcode\":\"IORING_OP_EPOLL_CTL\"").count(),
        1
    );

    let _ = fs::remove_dir_all(bombini_temp_dir);
}
