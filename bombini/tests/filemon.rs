mod common;
use common::*;
use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, mmap, truncate};
use tempfile::Builder;

use std::time::Duration;
use std::{
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
};

use more_asserts as ma;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

#[test]
fn test_6_2_filemon_open_filter() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
file_open:
  enabled: true
  rules:
  - rule: OpenTestRule
    scope: binary_name in ["ls", "tail"]
    event: path in ["/etc"] OR name == "filemon.yaml"
  - rule: OpenTestRule2
    scope: binary_name == "touch"
    event: name == "bombini_file_open_test_file.txt" AND creation_flags in ["O_CREAT", "O_TRUNC"] AND access_mode == "O_WRONLY"
"#;
    let _ = fs::write(&filemon_config, config_contents);
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let event_log =
        File::create(bombini_temp_dir.join("events.log")).expect("can't create events file");

    let bombini = Command::new(EXE_BOMBINI)
        .args([
            "--config-dir",
            tmp_config.to_str().unwrap(),
            "--bpf-objs",
            bpf_objs.to_str().unwrap(),
            "--detector",
            "procmon",
            "--detector",
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .stdout(event_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    let ls_usr = Command::new("ls")
        .args(["-lah", "/etc"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start ls");

    assert!(ls_usr.success());

    let tail_conf = Command::new("tail")
        .args([filemon_config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start tail");

    assert!(tail_conf.success());

    let bombini_test_file = bombini_temp_dir.join("bombini_file_open_test_file.txt");

    let tail_conf = Command::new("touch")
        .args([bombini_test_file.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start tail");

    assert!(tail_conf.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 3);
    ma::assert_ge!(events.matches("\"type\":\"FileOpen\"").count(), 3);
    ma::assert_ge!(events.matches("\"path\":\"/etc\"").count(), 1);
    ma::assert_ge!(events.matches("\"access_mode\":\"O_WRONLY\"").count(), 1);
    ma::assert_ge!(events.matches("\"creation_flags\":\"O_CREAT").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(bombini_test_file.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_truncate() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
path_truncate:
  enabled: true
  rules:
  - rule: TruncateTestRule
    event: path_prefix == "/tmp/bombini-test-"
"#;
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    // Create tmp file
    let tmp_file = Builder::new()
        .prefix("bombini-test-")
        .rand_bytes(5)
        .tempfile()
        .expect("can't create temp file");

    let _ = unsafe {
        truncate(
            tmp_file.path().to_str().unwrap().as_ptr() as *const libc::c_char,
            0,
        )
    };
    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathTruncate\"").count(), 1);
    assert_eq!(events.matches(tmp_file.path().to_str().unwrap()).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_unlink() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
path_unlink:
  enabled: true
  rules:
  - rule: UnlinkTestRule
    event: path_prefix == "/tmp/bombini-test-"
"#;
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    // Create tmp file
    let tmp_file = Builder::new()
        .prefix("bombini-test-")
        .rand_bytes(5)
        .tempfile()
        .expect("can't create temp file");

    let rm_status = Command::new("rm")
        .args([tmp_file.path().to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start rm");

    assert!(rm_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathUnlink\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"rm\"").count(), 1);
    assert_eq!(events.matches(tmp_file.path().to_str().unwrap()).count(), 4); // FileEvent + ProcInfo

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_symlink() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
path_symlink:
  enabled: true
  rules:
  - rule: SymlinkTestRule
    event: path_prefix == "/tmp/bombini-test-symlink-"
"#;
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    // Create tmp files
    let tmp_file_prefix = Builder::new()
        .prefix("bombini-test-symlink-")
        .rand_bytes(5)
        .tempfile()
        .expect("can't create temp file");
    let tmp_symlink_prefix = bombini_temp_dir.join("bombini_test_symlink_1");

    let tmp_file_not_match = bombini_temp_dir.join("bombini_hardlink_test_file_3");
    let tmp_symlink_not_match = bombini_temp_dir.join("bombini_test_symlink_3");
    let _ = File::create(&tmp_file_not_match).expect("can't create test file");

    fn create_symlink(src: &Path, dst: &Path) -> ExitStatus {
        let ln_status = Command::new("ln")
            .args(["-s", src.to_str().unwrap(), dst.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status()
            .expect("can't start ln");

        ln_status
    }

    assert!(create_symlink(&tmp_file_prefix.path(), &tmp_symlink_prefix).success());
    assert!(create_symlink(&tmp_file_not_match, &tmp_symlink_not_match).success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathSymlink\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"ln\"").count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(&tmp_file_prefix.path().to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(&tmp_file_not_match.to_str().unwrap());
    assert_ne!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_chmod() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
path_chmod:
  enabled: true
  rules:
  - rule: ChmodTestRule
    event: name == "filemon.yaml" AND mode in ["S_IWOTH", "S_IWGRP", "S_IWUSR"]
"#;
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    let chmod_status = Command::new("chmod")
        .args(["+w", filemon_config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start chmod");

    assert!(chmod_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathChmod\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"chmod\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_chown() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let filemon_config = tmp_config.join("filemon.yaml");
    let config_contents = r#"
path_chown:
  enabled: true
  rules:
  - rule: ChownTestRule
    event: name == "filemon.yaml" AND uid == 0 AND gid == 0
"#;
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    let chown_status = Command::new("chown")
        .args(["0:0", filemon_config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start chowm");

    assert!(chown_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathChown\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"chown\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_filemon_mmap_file() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let config_contents = r#"
mmap_file:
  enabled: true
"#;
    let filemon_config = tmp_config.join("filemon.yaml");
    let _ = fs::write(&filemon_config, config_contents);
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    let test_path = filemon_config.to_str().unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&test_path)
        .expect("Failed to open file");
    let fd = file.as_raw_fd();
    let mapped_ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            10 as usize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };

    if mapped_ptr == MAP_FAILED {
        panic!("mmap failed");
    }

    // Wait Events being processed
    thread::sleep(Duration::from_millis(2000));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"MmapFile\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(test_path);
    ma::assert_ge!(events.matches(&file_path).count(), 1);
    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_filemon_ioctl() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let config_contents = r#"
file_ioctl:
  enabled: true
  rules:
  - rule: IoctlTestRule
    event: path_prefix == "/dev" AND cmd in [4712, 2147766906, 769]
"#;
    let filemon_config = tmp_config.join("filemon.yaml");
    let _ = fs::write(&filemon_config, config_contents);
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
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
            "filemon",
        ])
        .env("RUST_LOG", "debug")
        .stderr(bombini_log.try_clone().unwrap())
        .spawn();

    if bombini.is_err() {
        panic!("{:?}", bombini.err().unwrap());
    }
    let mut bombini = bombini.expect("failed to start bombini");
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(2000));

    let fdisk_status = Command::new("fdisk")
        .args(["-l"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start fdisk");

    assert!(fdisk_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"FileIoctl\"").count(), 1);
    ma::assert_ge!(events.matches("\"path\":\"/dev/").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}
