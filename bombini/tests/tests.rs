use std::fs;

use std::process::{Command, Stdio};
use std::{thread, time::Duration};

use procfs::sys::kernel::Version;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use more_asserts as ma;

mod common;

use common::*;

#[test]
fn test_6_2_detectors_load() {
    let kernel_ver = Version::current().unwrap();
    let ver_6_8 = Version::new(6, 8, 0);

    let mut builder = BombiniBuilder::new();
    builder
        .detector("procmon", None)
        .detector("filemon", None)
        .detector("netmon", None);

    if kernel_ver >= ver_6_8 {
        builder
            .detector("io_uringmon", None)
            .detector("gtfobins", None);
    }

    let mut bombini = builder.bombini_start_timeout(7).launch().unwrap();

    // Wait for detectors being loaded
    thread::sleep(Duration::from_millis(1000));

    bombini.stop();

    let log = fs::read_to_string(bombini.get_working_dir().join("bombini.log"))
        .expect("can't read events");

    // Check loaded detectors
    assert!(log.contains("procmon is loaded"));
    assert!(log.contains("filemon is loaded"));
    assert!(log.contains("netmon is loaded"));
    if kernel_ver >= ver_6_8 {
        assert!(log.contains("gtfobins is loaded"));
        assert!(log.contains("io_uringmon is loaded"));
    }
}

#[test]
fn test_6_8_gtfobins_detector() {
    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("gtfobins", None)
        .events_timeout(1)
        .launch()
        .unwrap();

    let mut gtfo_proc = Command::new("sudo")
        .args(["xargs", "-a", "/dev/null", "sh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("can't start ls");

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"GTFOBinsEvent\"", 1)
        .unwrap();
    bombini.stop();

    let _ = signal::kill(Pid::from_raw(gtfo_proc.id() as i32), Signal::SIGKILL);
    let _ = gtfo_proc.wait().unwrap();

    print_example_events!(&events);
    assert_eq!(events.matches("\"type\":\"GTFOBinsEvent\"").count(), 1);
    assert_eq!(events.matches("\"filename\":\"xargs\"").count(), 7);
    assert_eq!(events.matches("\"args\":\"-a /dev/null sh\"").count(), 7);
}

#[test]
fn test_6_8_io_uringmon() {
    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("io_uringmon", None)
        .events_timeout(1)
        .launch()
        .unwrap();

    let _ = Command::new("nslookup")
        .args(["google.com"])
        .stdout(Stdio::null())
        .status()
        .expect("can't start nslookup");

    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"IOUringEvent\"", 1)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"filename\":\"nslookup\"").count(), 2);
    ma::assert_ge!(events.matches("\"args\":\"google.com\"").count(), 2);
    ma::assert_ge!(events.matches("\"type\":\"IOUringEvent\"").count(), 1);
    ma::assert_ge!(
        events.matches("\"opcode\":\"IORING_OP_EPOLL_CTL\"").count(),
        1
    );
}
