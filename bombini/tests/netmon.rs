mod common;
use common::bombini_launcher::*;

use std::time::Duration;
use std::{
    process::{Command, Stdio},
    thread,
};

use more_asserts as ma;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

#[test]
fn test_6_2_netmon_tcp_v4() {
    let config_contents = r#"
egress:
  enabled: true
  rules:
  - rule: NetMonIpv4Test
    event: ipv4_dst == "127.0.0.1" AND ipv4_src == "127.0.0.1" AND port_dst == 7878
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("netmon", Some(config_contents))
        .events_timeout(4)
        .launch()
        .unwrap();

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

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"NetworkEvent\"", 2)
        .unwrap();
    bombini.stop();

    let _ = signal::kill(Pid::from_raw(nc.id() as i32), Signal::SIGKILL);
    let _ = nc.wait().unwrap();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 2);
    ma::assert_ge!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"rule\":\"NetMonIpv4Test\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"TcpConnectionClose\"").count(), 1);
    ma::assert_ge!(events.matches("\"args\":\"localhost 7878\"").count(), 4);
}

#[test]
fn test_6_2_netmon_tcp_v6() {
    let config_contents = r#"
egress:
  enabled: true
  rules:
  - rule: NetMonIpv6Test
    event: ipv6_dst == "::1" AND port_dst == 7879
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("netmon", Some(config_contents))
        .events_timeout(4)
        .launch()
        .unwrap();

    let mut nc = Command::new("nc")
        .args(["-6", "-l", "7879"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    // Wait nc
    thread::sleep(Duration::from_millis(1500));

    let _ = Command::new("telnet")
        .args(["-6", "localhost", "7879"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start nc");

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"NetworkEvent\"", 2)
        .unwrap();
    bombini.stop();

    let _ = signal::kill(Pid::from_raw(nc.id() as i32), Signal::SIGKILL);
    let _ = nc.wait().unwrap();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"NetworkEvent\"").count(), 2);
    ma::assert_ge!(
        events
            .matches("\"type\":\"TcpConnectionEstablish\"")
            .count(),
        1
    );
    ma::assert_ge!(events.matches("\"rule\":\"NetMonIpv6Test\"").count(), 1);
    ma::assert_ge!(events.matches("\"type\":\"TcpConnectionClose\"").count(), 1);
    ma::assert_ge!(events.matches("\"args\":\"-6 localhost 7879\"").count(), 4);
}
