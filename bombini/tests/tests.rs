use std::os::fd::AsRawFd;
use std::{env, fs};

use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, memfd_create, mmap, truncate, write};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::{thread, time::Duration};

use procfs::sys::kernel::Version;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;
use tempfile::{Builder, TempDir};

static EXE_BOMBINI: &str = env!("CARGO_BIN_EXE_bombini");
static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[macro_export]
macro_rules! print_example_events {
    ($events:expr) => {
        #[cfg(feature = "examples")]
        {
            println!("{}", $events);
        }
    };
}

// Return Tmpdir, config, bpf_obj
fn init_test_env() -> (TempDir, PathBuf, PathBuf) {
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
        .disable_cleanup(true)
        .tempdir()
        .expect("can't create temp dir");
    (temp_dir, config, bpf_objs)
}

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
fn test_6_2_procmon() {
    let (temp_dir, config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let _ = fs::write(tmp_config.join("procmon.yaml"), "expose_events: true");
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
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);

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
  path_filter:
    prefix:
    - /tmp/bombini-test-
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
  path_filter:
    prefix:
    - /tmp/bombini-test-symlink-
    name:
    - bombini_hardlink_test_file_2
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

    let tmp_file_name = bombini_temp_dir.join("bombini_hardlink_test_file_2");
    let tmp_symlink_name = bombini_temp_dir.join("bombini_test_symlink_2");
    let _ = File::create(&tmp_file_name).expect("can't create test file");

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
    assert!(create_symlink(&tmp_file_name, &tmp_symlink_name).success());
    assert!(create_symlink(&tmp_file_not_match, &tmp_symlink_not_match).success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 2);
    ma::assert_ge!(events.matches("\"type\":\"PathSymlink\"").count(), 2);
    ma::assert_ge!(events.matches("\"filename\":\"ln\"").count(), 2);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(&tmp_file_prefix.path().to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(&tmp_file_name.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(&tmp_file_not_match.to_str().unwrap());
    assert_ne!(events.matches(&file_path).count(), 1);

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
  path_filter:
    prefix:
    - /tmp/bombini-test-
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
  path_filter:
    name:
    - filemon.yaml
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
  path_filter:
    name:
    - filemon.yaml
    path:
    - /etc
process_filter:
  binary:
    name:
      - ls
      - tail
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

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 2);
    ma::assert_ge!(events.matches("\"type\":\"FileOpen\"").count(), 2);
    ma::assert_ge!(events.matches("\"path\":\"/etc\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

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
  path_filter:
    prefix:
    - /dev
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
  path_filter:
    name:
    - filemon.yaml
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
fn test_6_2_netmon_tcp_ip4() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let netmon_config = tmp_config.join("netmon.yaml");
    let config_contents = r#"
egress:
  enabled: true
  ipv4_filter:
    dst_ip:
    - 127.0.0.1
    src_ip:
    - 127.0.0.1
"#;
    let _ = fs::write(&netmon_config, config_contents);
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
            "netmon",
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

    let mut nc = Command::new("nc")
        .args(["-l", "7878"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    // Wait nc
    thread::sleep(Duration::from_millis(500));

    let _ = Command::new("telnet")
        .args(["localhost", "7878"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(nc.id() as i32), Signal::SIGKILL);

    let _ = nc.wait().unwrap();

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    // inet_csk_accept isn't triggered from tests don't know why
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 2);
    ma::assert_ge!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"type\":\"TcpConnectionClose\"").count(), 1);
    assert_eq!(events.matches("\"args\":\"localhost 7878\"").count(), 4);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_netmon_tcp_ip6() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let netmon_config = tmp_config.join("netmon.yaml");
    let config_contents = r#"
egress:
  enabled: true
  ipv6_filter:
    dst_ip:
    - 2000::/3
"#;
    let _ = fs::write(&netmon_config, config_contents);
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
            "netmon",
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

    let _ = Command::new("wget")
        .args(["-qO-", "-6", "google.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start wget");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    // inet_csk_accept isn't triggered from tests don't know why
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 2);
    ma::assert_ge!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"args\":\"-qO- -6 google.com\"").count(), 2);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_iouring_allow_list() {
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
    let config_contents = r#"
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    name:
      - nslookup
"#;
    let _ = fs::write(tmp_config.join("io_uringmon.yaml"), config_contents);
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
fn test_6_2_procmon_setuid() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
setuid:
  enabled: true
  cred_filter:
    uid_filter:
      euid:
      - 0
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    prefix:
      - /usr/bin/
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let sudo_status = Command::new("sudo")
        .args(["-u", "nobody", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sudo");

    assert!(sudo_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setuid\"").count(), 1);
    ma::assert_ge!(events.matches("\"flags\":\"LSM_SETID_RES\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"sudo\"").count(), 1);
    ma::assert_ge!(events.matches("\"euid\":0").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_setgid() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
setgid:
  enabled: true
  cred_filter:
    gid_filter:
      egid:
      - 0
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    prefix:
      - /usr/bin/
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let sudo_status = Command::new("sudo")
        .args(["-u", "nobody", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sudo");

    assert!(sudo_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setgid\"").count(), 1);
    ma::assert_ge!(events.matches("\"flags\":\"LSM_SETID_RES\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"sudo\"").count(), 1);
    ma::assert_ge!(events.matches("\"euid\":0").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_setcaps() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
capset:
  enabled: true
  cred_filter:
    cap_filter:
      effective:
      - "CAP_NET_RAW"
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    name:
      - capsh
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let sudo_status = Command::new("sudo")
        .args([
            "capsh",
            "--caps=cap_sys_admin=ep cap_net_raw=ep",
            "--",
            "-c",
            "id",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sudo");

    assert!(sudo_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setcaps\"").count(), 1);
    assert_eq!(
        events
            .matches("\"effective\":\"CAP_NET_RAW | CAP_SYS_ADMIN\"")
            .count(),
        1
    );

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_prctl() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
prctl:
  enabled: true
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    path:
      - /usr/sbin/capsh
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let capsh_status = Command::new("capsh")
        .args(["--keep=1", "--", "-c", "echo KEEPCAPS enabled"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start capsh");

    assert!(capsh_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Prctl\"").count(), 1);
    assert_eq!(events.matches("\"PrSetKeepCaps\":1").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_create_user_ns() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
create_user_ns:
  enabled: true
  cred_filter:
    cap_filter:
      effective:
      - "CAP_SYS_ADMIN"
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let unshare_status = Command::new("unshare")
        .args(["-U"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start unshare");

    assert!(unshare_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"CreateUserNs\"").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_fileless_exec() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
setuid:
  enabled: false
capset:
  enabled: false
prctl:
  enabled: false
create_user_ns:
  enabled: false
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let fd = unsafe { memfd_create(CString::new("fileless-exec-test").unwrap().as_ptr(), 0) };
    if fd == -1 {
        panic!("memfd_create failed");
    }

    let data = fs::read("/bin/true").expect("Failed to read binary");

    let written = unsafe { write(fd, data.as_ptr() as *const _, data.len()) };
    if written != data.len() as isize {
        panic!("write to memfd failed");
    }
    let _ = Command::new(format!("/proc/self/fd/{}", fd))
        .args(["fileless-exec-test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("Failed to execute");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    assert_eq!(
        events
            .matches("\"filename\":\"memfd:fileless-exec-test\"")
            .count(),
        2
    );
    assert_eq!(
        events.matches("\"secureexec\":\"FILELESS_EXEC\"").count(),
        2
    );

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_procmon_ima() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
    if !cmdline.contains("ima") {
        println!("⚠️ IMA is disabled. Test is skipped.");
        return;
    }
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
ima_hash: true
setuid:
  enabled: false
capset:
  enabled: false
prctl:
  enabled: false
create_user_ns:
  enabled: false
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
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

    let calc_hash = format!(
        "sha256:{}",
        sha256::try_digest(Path::new("/usr/bin/ls")).unwrap()
    );

    let ls_status = Command::new("ls")
        .args(["-lah"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start ls");

    assert!(ls_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches(&calc_hash).count(), 2);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}
