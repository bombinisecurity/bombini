use std::fs;

use libc::{memfd_create, write};
use std::ffi::CString;
use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;

mod common;

use common::*;

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
  rules:
  - rule: ProcMonSetuid
    scope: binary_prefix == "/usr/bin"
    event: euid == 0
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
  rules:
  - rule: ProcMonSetgid
    scope: binary_prefix == "/usr/bin"
    event: egid == 0
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
  rules:
  - rule: ProcMonSetcaps
    scope: binary_name == "capsh"
    event: ecaps in [ "CAP_NET_RAW" ]
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
  rules:
  - rule: ProcMonPrctl
    scope: binary_path == "/usr/sbin/capsh"
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
  rules:
  - rule: ProcMonCreateUserNs
    event: ecaps == "CAP_SYS_ADMIN"
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
