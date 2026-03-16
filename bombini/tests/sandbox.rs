use std::fs;

use std::fs::File;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;

mod common;

use common::*;

#[test]
fn test_6_2_sandbox_filemon_open() {
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
  sandbox:
    enabled: true
    deny_list: true
  rules:
  - rule: OpenTestSandBoxRule
    scope: binary_name in ["dash", "sh", "bash"]
    event: name == "filemon.yaml"  AND access_mode == "O_WRONLY"
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
            "--log-file",
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

    let config_path = filemon_config.to_str().expect("Invalid path");

    let sh = Command::new("sh")
        .args(["-c", &format!("echo 'Hello' > {}", config_path)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sh");

    assert!(!sh.success());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"FileOpen\"").count(), 1);
    ma::assert_ge!(
        events.matches("\"rule\":\"OpenTestSandBoxRule\"").count(),
        1
    );
    assert_eq!(events.matches("\"blocked\":true").count(), 1);
    ma::assert_ge!(events.matches("\"access_mode\":\"O_WRONLY\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(&filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_sandbox_procmon_bprm_check() {
    let (temp_dir, mut config, bpf_objs) = init_test_env();
    let bombini_temp_dir = temp_dir.path();
    let mut tmp_config = bombini_temp_dir.join("config/config.yaml");
    let _ = fs::create_dir(bombini_temp_dir.join("config"));
    let _ = fs::copy(&config, &tmp_config);
    tmp_config.pop();
    config.pop();
    let config_contents = r#"
bprm_check:
  enabled: true
  sandbox:
    enabled: true
  rules:
  - rule: BprmCheckTestRule
    event: path_prefix in ["/usr", "/bin", "/sbin", "/home"]
"#;
    let procmon_config = tmp_config.join("procmon.yaml");
    let _ = fs::write(&procmon_config, config_contents);
    let bombini_log =
        File::create(bombini_temp_dir.join("bombini.log")).expect("can't create log file");
    let event_log = temp_dir.path().join("events.log");

    let bombini = Command::new(EXE_BOMBINI)
        .args([
            "--config-dir",
            tmp_config.to_str().unwrap(),
            "--bpf-objs",
            bpf_objs.to_str().unwrap(),
            "--log-file",
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
    thread::sleep(Duration::from_millis(2000));

    let system_ls = which::which("ls").expect("ls not found in PATH");
    let copied_ls = bombini_temp_dir.join("ls");
    fs::copy(&system_ls, &copied_ls).expect("failed to copy ls");

    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&copied_ls)
            .expect("can't read ls metadata")
            .permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(&copied_ls, perms).expect("can't set executable permissions");
    }

    let ls_status = Command::new(&copied_ls)
        .args(["-lah"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status();

    assert!(ls_status.is_err());

    // Wait Events being processed
    thread::sleep(Duration::from_millis(500));

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events =
        fs::read_to_string(bombini_temp_dir.join("events.log")).expect("can't read events");
    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"BprmCheck\"").count(), 1);
    assert_eq!(events.matches("\"rule\":\"BprmCheckTestRule\"").count(), 1);
    assert_eq!(events.matches("\"blocked\":true").count(), 1);
    let mut file_path = String::from("\"binary\":\"");
    file_path.push_str(&copied_ls.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}
