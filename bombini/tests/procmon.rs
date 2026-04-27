mod common;
use base64::Engine;
use common::bombini_launcher::*;

use libc::{memfd_create, write};
use std::ffi::CString;
use std::fs::{self};
use std::path::Path;
use std::process::{Command, Stdio};

use more_asserts as ma;

#[test]
fn test_6_2_procmon_ima() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap();
    if !cmdline.contains("ima") {
        println!("⚠️ IMA is disabled. Test is skipped.");
        return;
    }

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

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

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
    let events = bombini.wait_for_events("\"filename\":\"ls\"", 2).unwrap();
    bombini.stop();

    print_example_events!(&events);
    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches(&calc_hash).count(), 2);
}

#[test]
fn test_6_2_procmon() {
    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .events_timeout(1)
        .launch()
        .unwrap();

    let _ = Command::new("ls")
        .args(["-lah"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start ls");

    // Wait Events being processed
    let events = bombini.wait_for_events("\"filename\":\"ls\"", 2).unwrap();
    bombini.stop();

    assert_eq!(events.matches("\"filename\":\"ls\"").count(), 2);
    assert_eq!(events.matches("\"args\":\"-lah\"").count(), 2);

    fn get_field_from_event(events: &str, field: &str) -> String {
        let json_field = "\"".to_owned() + field + "\":";
        let field_start_idx = events
            .find(&json_field)
            .expect(&format!("{} not found", field))
            + json_field.len();
        let field_end_idx = events[field_start_idx..]
            .find(|c| c == ',' || c == '}')
            .unwrap()
            + field_start_idx;
        events[field_start_idx..field_end_idx]
            .trim_matches('"')
            .to_owned()
    }

    let exec_id_base64 = get_field_from_event(&events, "exec_id");
    let binding = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&exec_id_base64)
        .expect(&format!("can't decode exec_id: {}", exec_id_base64));
    let exec_id = String::from_utf8_lossy(binding.as_slice());
    let (exec_pid, _) = exec_id.split_once(':').unwrap();
    let pid = get_field_from_event(&events, "pid");
    assert_eq!(exec_pid, pid);

    let exec_id_base64 = get_field_from_event(&events, "parent_exec_id");
    let binding = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&exec_id_base64)
        .expect(&format!("can't decode parent_exec_id: {}", exec_id_base64));
    let exec_id = String::from_utf8_lossy(binding.as_slice());
    let (exec_ppid, _) = exec_id.split_once(':').unwrap();
    let ppid = get_field_from_event(&events, "ppid");
    assert_eq!(exec_ppid, ppid);
}

#[test]
fn test_6_2_procmon_setuid() {
    let config_contents = r#"
setuid:
  enabled: true
  rules:
  - rule: ProcMonSetuid
    scope: binary_prefix == "/usr/bin"
    event: euid == 0
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let sudo_status = Command::new("sudo")
        .args(["-u", "nobody", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sudo");

    assert!(sudo_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"ProcessEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setuid\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ProcMonSetuid\"").count(), 1);
    ma::assert_ge!(events.matches("\"flags\":\"LSM_SETID_RES\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"sudo\"").count(), 1);
    ma::assert_ge!(events.matches("\"euid\":0").count(), 1);
}

#[test]
fn test_6_2_procmon_setgid() {
    let config_contents = r#"
setgid:
  enabled: true
  rules:
  - rule: ProcMonSetgid
    scope: binary_prefix == "/usr/bin"
    event: egid == 0
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let sudo_status = Command::new("sudo")
        .args(["-u", "nobody", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sudo");

    assert!(sudo_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"ProcessEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setgid\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ProcMonSetgid\"").count(), 1);
    ma::assert_ge!(events.matches("\"flags\":\"LSM_SETID_RES\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"sudo\"").count(), 1);
    ma::assert_ge!(events.matches("\"euid\":0").count(), 1);
}

#[test]
fn test_6_2_procmon_setcaps() {
    let config_contents = r#"
capset:
  enabled: true
  rules:
  - rule: ProcMonSetcaps
    scope: binary_name == "capsh"
    event: ecaps in [ "CAP_NET_RAW" ]
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

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
    let events = bombini
        .wait_for_events("\"type\":\"ProcessEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Setcaps\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ProcMonSetcaps\"").count(), 1);
    assert_eq!(
        events
            .matches("\"effective\":\"CAP_NET_RAW | CAP_SYS_ADMIN\"")
            .count(),
        1
    );
}

#[test]
fn test_6_2_procmon_prctl() {
    let config_contents = r#"
prctl:
  enabled: true
  rules:
  - rule: ProcMonPrctl
    scope: binary_path == "/usr/sbin/capsh"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let capsh_status = Command::new("capsh")
        .args(["--keep=1", "--", "-c", "echo KEEPCAPS enabled"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start capsh");

    assert!(capsh_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"ProcessEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"Prctl\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ProcMonPrctl\"").count(), 1);
    assert_eq!(events.matches("\"PrSetKeepCaps\":1").count(), 1);
}

#[test]
fn test_6_2_procmon_create_user_ns() {
    let config_contents = r#"
create_user_ns:
  enabled: true
  rules:
  - rule: ProcMonCreateUserNs
    event: ecaps == "CAP_SYS_ADMIN"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let unshare_status = Command::new("unshare")
        .args(["-U"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start unshare");

    assert!(unshare_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"ProcessEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"ProcessEvent\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"CreateUserNs\"").count(), 1);
    assert_eq!(
        events.matches("\"rule\":\"ProcMonCreateUserNs\"").count(),
        1
    );
}

#[test]
fn test_6_2_procmon_fileless_exec() {
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

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

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
    let events = bombini
        .wait_for_events("\"secureexec\":\"FILELESS_EXEC\"", 2)
        .unwrap();
    bombini.stop();

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
}
