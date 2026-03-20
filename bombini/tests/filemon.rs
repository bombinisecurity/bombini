mod common;
use common::*;
use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, mmap, truncate};
use tempfile::Builder;

use std::ffi::CString;
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, ExitStatus, Stdio},
};

use more_asserts as ma;

#[test]
fn test_6_2_filemon_open_filter() {
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

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    let ls_usr = Command::new("ls")
        .args(["-lah", "/etc"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start ls");

    assert!(ls_usr.success());

    let filemon_config = bombini_temp_dir.join("config/filemon.yaml");

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
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 3)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 3);
    ma::assert_ge!(events.matches("\"type\":\"FileOpen\"").count(), 3);
    ma::assert_ge!(events.matches("\"rule\":\"OpenTestRule\"").count(), 2);
    ma::assert_ge!(events.matches("\"rule\":\"OpenTestRule2\"").count(), 1);
    ma::assert_ge!(events.matches("\"path\":\"/etc\"").count(), 1);
    ma::assert_ge!(events.matches("\"access_mode\":\"O_WRONLY\"").count(), 1);
    ma::assert_ge!(events.matches("\"creation_flags\":\"O_CREAT").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(bombini_test_file.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_truncate() {
    let config_contents = r#"
path_truncate:
  enabled: true
  rules:
  - rule: TruncateTestRule
    event: path_prefix == "/tmp/bombini-test-"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    // Create tmp file in bombini_temp_dir
    let tmp_file_path = bombini_temp_dir.join("bombini-test-truncate");
    let _ = File::create(&tmp_file_path).expect("can't create temp file");

    let cstring = CString::new(tmp_file_path.to_str().unwrap()).unwrap();

    let _ = unsafe { truncate(cstring.as_ptr() as *const libc::c_char, 0) };

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathTruncate\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"TruncateTestRule\"").count(), 1);
    assert_eq!(events.matches(tmp_file_path.to_str().unwrap()).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_unlink() {
    let config_contents = r#"
path_unlink:
  enabled: true
  rules:
  - rule: UnlinkTestRule
    event: path_prefix == "/tmp/bombini-test-"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    // Create tmp file in bombini_temp_dir
    let tmp_file_path = bombini_temp_dir.join("bombini-test-unlink");
    let _ = File::create(&tmp_file_path).expect("can't create temp file");

    let rm_status = Command::new("rm")
        .args([tmp_file_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start rm");

    assert!(rm_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathUnlink\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"UnlinkTestRule\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"rm\"").count(), 1);
    assert_eq!(events.matches(tmp_file_path.to_str().unwrap()).count(), 4); // FileEvent + ProcInfo

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_symlink() {
    let config_contents = r#"
path_symlink:
  enabled: true
  rules:
  - rule: SymlinkTestRule
    event: path_prefix == "/tmp/bombini-test-symlink-"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

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
        Command::new("ln")
            .args(["-s", src.to_str().unwrap(), dst.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status()
            .expect("can't start ln")
    }

    assert!(create_symlink(tmp_file_prefix.path(), &tmp_symlink_prefix).success());
    assert!(create_symlink(&tmp_file_not_match, &tmp_symlink_not_match).success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathSymlink\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"SymlinkTestRule\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"ln\"").count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(tmp_file_prefix.path().to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);
    let mut file_path = String::from("\"old_path\":\"");
    file_path.push_str(tmp_file_not_match.to_str().unwrap());
    assert_ne!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_chmod() {
    let config_contents = r#"
path_chmod:
  enabled: true
  rules:
  - rule: ChmodTestRule
    event: name == "filemon.yaml" AND mode in ["S_IWOTH", "S_IWGRP", "S_IWUSR"]
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    let filemon_config = bombini_temp_dir.join("config/filemon.yaml");

    let chmod_status = Command::new("chmod")
        .args(["+w", filemon_config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start chmod");

    assert!(chmod_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathChmod\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ChmodTestRule\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"chmod\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_8_filemon_chown() {
    let config_contents = r#"
path_chown:
  enabled: true
  rules:
  - rule: ChownTestRule
    event: name == "filemon.yaml" AND uid == 0 AND gid == 0
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    let filemon_config = bombini_temp_dir.join("config/filemon.yaml");

    let chown_status = Command::new("chown")
        .args(["0:0", filemon_config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start chown");

    assert!(chown_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"PathChown\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"ChownTestRule\"").count(), 1);
    ma::assert_ge!(events.matches("\"filename\":\"chown\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(filemon_config.to_str().unwrap());
    assert_eq!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_filemon_mmap_file() {
    let config_contents = r#"
mmap_file:
  enabled: true
  rules:
  - rule: MmapFileTestRule
    event: prot_mode == "PROT_WRITE" AND flags in ["MAP_SHARED", "MAP_EXECUTABLE"]
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(2)
        .launch()
        .unwrap();

    let bombini_temp_dir = bombini.get_working_dir();

    let filemon_config = bombini_temp_dir.join("config/filemon.yaml");
    let test_path = filemon_config.to_str().unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(test_path)
        .expect("Failed to open file");
    let fd = file.as_raw_fd();
    let mapped_ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            10_usize,
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
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"MmapFile\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"MmapFileTestRule\"").count(), 1);
    ma::assert_ge!(
        events
            .matches("\"prot\":\"PROT_READ | PROT_WRITE\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"flags\":\"MAP_SHARED\"").count(), 1);
    let mut file_path = String::from("\"path\":\"");
    file_path.push_str(test_path);
    ma::assert_ge!(events.matches(&file_path).count(), 1);

    let _ = std::fs::remove_dir_all(bombini_temp_dir);
}

#[test]
fn test_6_2_filemon_ioctl() {
    let config_contents = r#"
file_ioctl:
  enabled: true
  rules:
  - rule: IoctlTestRule
    event: path_prefix == "/dev" AND cmd in [4712, 2147766906, 769]
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("filemon", Some(config_contents))
        .events_timeout(1)
        .launch()
        .unwrap();

    let fdisk_status = Command::new("fdisk")
        .args(["-l"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .expect("can't start fdisk");

    assert!(fdisk_status.success());

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"FileEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"FileEvent\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"FileIoctl\"").count(), 1);
    ma::assert_ge!(events.matches("\"rule\":\"IoctlTestRule\"").count(), 1);
    ma::assert_ge!(events.matches("\"path\":\"/dev/").count(), 1);
}
