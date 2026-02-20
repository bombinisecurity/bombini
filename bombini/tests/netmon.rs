mod common;
use common::*;

use std::time::Duration;
use std::{
    fs::{self, File},
    process::{Command, Stdio},
    thread,
};

use more_asserts as ma;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

#[test]
fn test_6_2_netmon_tcp_new() {
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
  rules:
  - rule: NetMonIpv4Test
    event: ipv4_dst == "127.0.0.1" AND ipv4_src == "127.0.0.1" AND port_dst == 7878
  - rule: NetMonIpv6Test
    event: ipv6_dst == "2000::/3" AND port_dst in [80, 443]
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
    thread::sleep(Duration::from_millis(4000));

    let mut nc = Command::new("nc")
        .args(["-l", "7878"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    // Wait nc
    thread::sleep(Duration::from_millis(1500));

    let _ = Command::new("telnet")
        .args(["localhost", "7878"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    let _ = Command::new("curl")
        .args(["-q", "-6", "google.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start curl");

    // Wait Events being processed
    thread::sleep(Duration::from_millis(1500));

    let _ = signal::kill(Pid::from_raw(nc.id() as i32), Signal::SIGKILL);

    let _ = nc.wait().unwrap();

    let _ = signal::kill(Pid::from_raw(bombini.id() as i32), Signal::SIGINT);

    let _ = bombini.wait().unwrap();

    let events = fs::read_to_string(&event_log).expect("can't read events");
    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 3);
    ma::assert_ge!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        2
    );
    ma::assert_ge!(events.matches("\"args\":\"-q -6 google.com\"").count(), 3);
    ma::assert_ge!(events.matches("\"type\":\"TcpConnectionClose\"").count(), 1);
    ma::assert_ge!(events.matches("\"args\":\"localhost 7878\"").count(), 4);

    let _ = fs::remove_dir_all(bombini_temp_dir);
}
