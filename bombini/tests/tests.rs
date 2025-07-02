use std::{env, fs};

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;
use tempfile::{Builder, TempDir};

static EXE_BOMBINI: &str = env!("CARGO_BIN_EXE_bombini");
static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");

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
fn test_detectors_load() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    config.pop();

    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");

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
    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(4000));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let log = fs::read_to_string(bombini_temp_dir.join("bombini.log")).expect("can't read events");

    // Check loaded detectors
    assert!(log.contains("gtfobins is loaded"));
    assert!(log.contains("procmon is loaded"));
    assert!(log.contains("histfile is loaded"));
    assert!(log.contains("filemon is loaded"));
    assert!(log.contains("netmon is loaded"));
    assert!(log.contains("io_uringmon is loaded"));

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_procmon_file() {
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

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_gtfobins_detector_file() {
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

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"type\":\"GTFOBinsEvent\"").count(), 1);
    assert_eq!(events.matches("\"filename\":\"xargs\"").count(), 1);
    assert_eq!(events.matches("\"args\":\"-a /dev/null sh\"").count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_filemon_unlink_file() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let _ = fs::copy(config.join("filemon.yaml"), tmp_config.join("filemon.yaml"));
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

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathUnlink\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"rm\"").count(), 1);
    assert_eq!(events.matches(tmp_file.path().to_str().unwrap()).count(), 2); // FileEvent + ProcInfo

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_netmon_tcp_ip4_file() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let _ = fs::copy(config.join("netmon.yaml"), tmp_config.join("netmon.yaml"));
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

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    // inet_csk_accept isn't triggered from tests don't know why
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 2);
    assert_eq!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"type\":\"TcpConnectionClose\"").count(), 1);
    assert_eq!(events.matches("\"args\":\"localhost 7878\"").count(), 2);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_procmon_allow_list_file() {
    let (temp_dir, config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let config_contents = r#"
expose_events: true
process_filter:
  uid:
    - 0
  euid:
    - 0
  binary:
    name:
      - tail
      - curl
    prefix:
      - /usr/bin/l
    path:
      - /usr/bin/uname
"#;
    let _ = fs::write(tmp_config.join("procmon.yaml"), config_contents);
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

    let _ = Command::new("uname")
        .args(["-a"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start uname");

    let _ = Command::new("tail")
        .args(["--help"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start tail");

    let _ = Command::new("ls")
        .args(["-lah"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start ls");

    let _ = Command::new("cat")
        .args(["--help"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start cat");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"filename\":\"uname\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-a\"").count(), 2);
    assert_eq!(events.matches("\"filename\":\"tail\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"--help\"").count(), 2);
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);
    assert_eq!(events.matches("\"filename\":\"cat\"").count(), 0);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_procmon_deny_list_file() {
    let (temp_dir, config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let config_contents = r#"
expose_events: true
process_filter:
  deny_list: true
  binary:
    name:
      - tail
"#;
    let _ = fs::write(tmp_config.join("procmon.yaml"), config_contents);
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

    let _ = Command::new("tail")
        .args(["--help"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start tail");

    let _ = Command::new("ls")
        .args(["-lah"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start ls");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    assert_eq!(events.matches("\"filename\":\"tail\"").count(), 0);
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_iouring_allow_list_file() {
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

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
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
fn test_filemon_open_allow_list_file() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let _ = fs::copy(config.join("procmon.yaml"), tmp_config.join("procmon.yaml"));
    let config_contents = r#"
file_open:
  disable: false
path_truncate:
  disable: true
path_unlink:
  disable: true
process_filter:
  binary:
    name:
      - tail
    path:
      - /usr/bin/cat
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
    let tail_status = Command::new("tail")
        .args([test_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start tail");

    assert!(tail_status.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    // TODO: more precise check
    let events = fs::read_to_string(&event_log).expect("can't read events");
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"FileOpen\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"tail\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&test_path);
    assert_eq!(events.matches(&file_path).count(), 1);
    let _ = fs::remove_dir_all(bombini_temp_dir);
}
