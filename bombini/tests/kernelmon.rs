mod common;
use common::bombini_launcher::*;

use more_asserts as ma;

#[test]
fn test_6_2_kernelmon_bpf() {
    let config_contents = r#"
bpf_map_create:
  enabled: true
  rules:
  - rule: "KernelMonBpfMapCreateTest"
    event: type == "BPF_MAP_TYPE_HASH" AND name == "AT_exec_count"
bpf_map:
  enabled: true
  rules:
  - rule: "KernelMonBpfMapTest"
    event: type == "BPF_MAP_TYPE_HASH" AND prefix == "AT_exec"
bpf_prog_load:
  enabled: true
  rules:
  - rule: "KernelMonBpfProgLoadTest"
    event: type == "BPF_PROG_TYPE_TRACING" AND prefix == "rawtracepoint"
bpf_prog:
  enabled: true
  rules:
  - rule: "KernelMonBpfProgTest"
    event: type == "BPF_PROG_TYPE_TRACING" AND name == "rawtracepoint_v"
"#;

    let mut bombini = BombiniBuilder::new()
        .detector("procmon", None)
        .detector("kernelmon", Some(config_contents))
        .events_timeout(8)
        .launch()
        .unwrap();

    let _ = common::bpftrace_launcher::BpfTrace::start();
    // Wait Events being processed
    let events = bombini
        .wait_for_events("\"type\":\"KernelEvent\"", 4)
        .unwrap();
    bombini.stop();

    print_example_events!(&events);
    ma::assert_ge!(events.matches("\"type\":\"KernelEvent\"").count(), 4);

    ma::assert_ge!(events.matches("\"type\":\"BpfMapCreate\"").count(), 1);
    ma::assert_ge!(events.matches("\"name\":\"AT_exec_count\"").count(), 1);
    ma::assert_ge!(
        events
            .matches("\"rule\":\"KernelMonBpfMapCreateTest\"")
            .count(),
        1
    );

    ma::assert_ge!(events.matches("\"type\":\"BpfMapAccess\"").count(), 1);
    ma::assert_ge!(
        events.matches("\"map_type\":\"BPF_MAP_TYPE_HASH\"").count(),
        1
    );
    ma::assert_ge!(
        events.matches("\"rule\":\"KernelMonBpfMapTest\"").count(),
        1
    );

    ma::assert_ge!(events.matches("\"type\":\"BpfProgLoad\"").count(), 1);
    ma::assert_ge!(events.matches("\"name\":\"rawtracepoint_v\"").count(), 1);
    ma::assert_ge!(
        events
            .matches("\"prog_type\":\"BPF_PROG_TYPE_TRACING\"")
            .count(),
        1
    );
    ma::assert_ge!(
        events
            .matches("\"rule\":\"KernelMonBpfProgLoadTest\"")
            .count(),
        1
    );

    ma::assert_ge!(events.matches("\"type\":\"BpfProgAccess\"").count(), 1);
    ma::assert_ge!(events.matches("\"hook\":\"sched_process_exec\"").count(), 1);
    ma::assert_ge!(
        events.matches("\"rule\":\"KernelMonBpfProgTest\"").count(),
        1
    );
}
