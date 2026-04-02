use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub(crate) struct BpfTrace(Child);

const BPF_PROG_RAW_TP: &str = "sched_process_exec";

impl BpfTrace {
    pub fn start() -> Self {
        let bpftrace = Self::get_bpftrace();

        let mut bpftrace = Command::new(bpftrace)
            .args(["-v", "-e", &format!("rawtracepoint:{BPF_PROG_RAW_TP} {{ @exec_count[str(((struct linux_binprm *)arg2)->filename)]++; }}")])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("Cannot start bpftrace");

        let stderr = BufReader::new(bpftrace.stderr.take().unwrap());

        static STARTED: AtomicBool = AtomicBool::new(false);

        let h = std::thread::spawn(move || {
            for line in stderr.lines().map_while(Result::ok) {
                if line.contains("Attached 1 probe") {
                    STARTED.store(true, Relaxed);
                    break;
                }
            }
        });

        for _ in 0..10 {
            if STARTED.load(Relaxed) || h.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }

        assert!(STARTED.load(Relaxed), "bpftrace is not started properly");

        BpfTrace(bpftrace)
    }

    fn get_bpftrace() -> PathBuf {
        let Ok(bpftrace) = which::which("bpftrace") else {
            panic!("bpftrace is not installed");
        };
        let version_output = Command::new(&bpftrace)
            .arg("--version")
            .output()
            .expect("Cannot run bpftrace --version");

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        let version = version_str
            .trim()
            .strip_prefix("bpftrace v")
            .expect("Unexpected bpftrace --version output format");

        let parts: Vec<u32> = version
            .split('.')
            .map(|p| p.parse().expect("Cannot parse bpftrace version component"))
            .collect();

        assert!(
            parts.len() == 3,
            "Unexpected bpftrace version format: {version}"
        );

        let (major, minor, patch) = (parts[0], parts[1], parts[2]);
        assert!(
            (major, minor, patch) >= (0, 24, 0),
            "bpftrace version must be greater or equal to v0.24.0, found v{version}"
        );

        bpftrace
    }
}

impl Drop for BpfTrace {
    fn drop(&mut self) {
        self.0.kill().expect("Cannot kill bpftrace");
    }
}
