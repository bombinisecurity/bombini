use std::fs;

use std::process::{Command, Stdio};

use more_asserts as ma;

mod common;

use common::*;

#[test]
fn test_6_2_sandbox_procmon_bprm_check() {
    let config_contents = r#"
bprm_check:
  enabled: true
  sandbox:
    enabled: true
  rules:
  - rule: BprmCheckTestRule
    event: path_prefix in ["/usr", "/bin", "/sbin", "/home"]
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

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
    let events = bombini
        .wait_for_events("\"type\":\"BprmCheck\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"BprmCheck\"").count(), 1);
    assert_eq!(events.matches("\"rule\":\"BprmCheckTestRule\"").count(), 1);
    assert_eq!(events.matches("\"blocked\":true").count(), 1);
    let mut file_path = String::from("\"binary\":\"");
    file_path.push_str(copied_ls.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_sandbox_filemon_open() {
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

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();
    let filemon_config = bombini_temp_dir.join("config/filemon.yaml");

    let sh = Command::new("sh")
        .args([
            "-c",
            &format!("echo 'Hello' > {}", filemon_config.to_str().unwrap()),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start sh");

    assert!(!sh.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

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
    file_path.push_str(filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}
