use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::Context;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::{Builder, TempDir};

pub static EXE_BOMBINI: &str = env!("CARGO_BIN_EXE_bombini");
pub static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");

static BOMBINI_TESTDATA_CONFIG_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/config");

#[macro_export]
macro_rules! print_example_events {
    ($events:expr) => {
        #[cfg(feature = "examples")]
        {
            println!("{}", $events);
        }
    };
}

pub struct BombiniBuilder {
    detectors: HashMap<String, Option<String>>,
    temp_dir_prefix: String,

    bombini_timeout: Duration,
    events_timeout: Duration,
}

pub struct BombiniCommand {
    bombini: BombiniProcess,
    paths: BombiniPathManager,

    bombini_timeout: Duration,
    events_timeout: Duration,
}

struct BombiniProcess {
    process: std::process::Child,
    bombini_log: PathBuf,
    event_log: PathBuf,
    exited: bool,
}

struct BombiniPathManager {
    temp_dir: TempDir,
    bombini_config_dir: PathBuf,
    bpf_objs: PathBuf,
}

impl Default for BombiniBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BombiniBuilder {
    pub fn new() -> Self {
        Self {
            detectors: HashMap::new(),
            temp_dir_prefix: "bombini-test-".to_string(),

            bombini_timeout: Duration::from_secs(5),
            events_timeout: Duration::from_secs(5),
        }
    }

    pub fn detector(&mut self, name: &str, config: Option<&str>) -> &mut BombiniBuilder {
        self.detectors
            .insert(name.to_string(), config.map(|s| s.to_string()));
        self
    }

    pub fn bombini_timeout(&mut self, secs: u64) -> &mut BombiniBuilder {
        self.bombini_timeout = Duration::from_secs(secs);
        self
    }

    pub fn events_timeout(&mut self, secs: u64) -> &mut BombiniBuilder {
        self.events_timeout = Duration::from_secs(secs);
        self
    }

    pub fn temp_dir_prefix(&mut self, prefix: &str) -> &mut BombiniBuilder {
        self.temp_dir_prefix = prefix.to_string();
        self
    }

    pub fn launch(&self) -> Result<BombiniCommand, anyhow::Error> {
        let path_manager = self.prepare_test_data()?;
        let bombini = self.launch_bombini(&path_manager)?;

        let cmd = BombiniCommand {
            bombini,
            paths: path_manager,
            bombini_timeout: self.bombini_timeout,
            events_timeout: self.events_timeout,
        };

        cmd.wait_for_bombini_start()?;
        Ok(cmd)
    }

    fn prepare_test_data(&self) -> Result<BombiniPathManager, anyhow::Error> {
        let mut bpf_objs = PathBuf::from(PROJECT_DIR);
        bpf_objs.pop();
        bpf_objs.push("target/bpfel-unknown-none");
        if EXE_BOMBINI.contains("release") {
            bpf_objs.push("release");
        } else {
            bpf_objs.push("debug");
        }

        let temp_dir = Builder::new()
            .prefix(self.temp_dir_prefix.as_str())
            .rand_bytes(5)
            .disable_cleanup(true)
            .tempdir()?;
        println!("{}", temp_dir.path().to_str().unwrap());

        let bombini_config_dir = self.init_configs(&temp_dir)?;

        Ok(BombiniPathManager {
            temp_dir,
            bombini_config_dir,
            bpf_objs,
        })
    }

    fn init_configs(&self, temp_dir: &TempDir) -> Result<PathBuf, anyhow::Error> {
        let testdata_config_dir = PathBuf::from(BOMBINI_TESTDATA_CONFIG_DIR);
        let bombini_config_dir = temp_dir.path().join("config");

        std::fs::create_dir(&bombini_config_dir)?;
        std::fs::copy(
            testdata_config_dir.join("config.yaml"),
            bombini_config_dir.join("config.yaml"),
        )?;

        for (name, detector_config) in &self.detectors {
            let config_path = bombini_config_dir.join(name).with_extension("yaml");
            if let Some(config) = detector_config {
                std::fs::write(&config_path, config)?;
            } else {
                std::fs::copy(
                    testdata_config_dir.join(name).with_extension("yaml"),
                    &config_path,
                )?;
            }
        }

        Ok(bombini_config_dir)
    }

    fn launch_bombini(
        &self,
        path_manager: &BombiniPathManager,
    ) -> Result<BombiniProcess, anyhow::Error> {
        let bombini_log = path_manager.temp_dir.path().join("bombini.log");
        let bombini_log_file = File::create(&bombini_log).expect("can't create log file");
        let event_log = path_manager.temp_dir.path().join("events.log");

        let mut cmd = std::process::Command::new(EXE_BOMBINI);
        cmd.args([
            "--config-dir",
            path_manager.bombini_config_dir.to_str().unwrap(),
            "--bpf-objs",
            path_manager.bpf_objs.to_str().unwrap(),
            "--log-file",
            event_log.to_str().unwrap(),
        ]);
        self.detectors.keys().for_each(|d| {
            cmd.args(["--detector", d]);
        });
        cmd.env("RUST_LOG", "debug").stderr(bombini_log_file);

        let child = cmd
            .spawn()
            .with_context(|| format!("can't start bombini: {:?}", cmd.get_args()))?;

        let bombini = BombiniProcess {
            process: child,
            bombini_log,
            event_log,
            exited: false,
        };

        Ok(bombini)
    }
}

impl BombiniCommand {
    pub fn wait_for_events(
        &self,
        event_match: &str,
        number_of_events: usize,
    ) -> Result<String, anyhow::Error> {
        self.wait_for_log_events(
            self.bombini.event_log.as_path(),
            event_match,
            number_of_events,
            self.events_timeout,
            true,
        )
        .with_context(|| "timeout waiting for events")
    }

    fn wait_for_bombini_start(&self) -> Result<(), anyhow::Error> {
        self.wait_for_log_events(
            self.bombini.bombini_log.as_path(),
            "All detectors are loaded, listening for events",
            1,
            self.bombini_timeout,
            false,
        )
        .map(|_| ())
        .with_context(|| "timeout waiting for bombini start")
    }

    fn wait_for_log_events(
        &self,
        log_path: &Path,
        event_match: &str,
        number_of_events: usize,
        timeout: Duration,
        return_log: bool,
    ) -> Result<String, anyhow::Error> {
        let log_path_cloned = log_path.to_path_buf();

        let match_count = Arc::new(AtomicUsize::new(0));
        let match_count_clone = Arc::clone(&match_count);
        let event_match = event_match.to_string();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel);

        let reader_handle = thread::spawn(move || {
            let file = File::open(log_path_cloned).expect("can't open log file");
            let mut reader = BufReader::new(file);
            let mut line = String::new();

            loop {
                if cancel_clone.load(Ordering::Relaxed) {
                    return;
                }

                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        // EOF — waiting for logs
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Ok(_) => {
                        if line.contains(&event_match) {
                            match_count_clone.fetch_add(1, Ordering::Relaxed);
                        }
                        if match_count_clone.load(Ordering::Relaxed) >= number_of_events {
                            return;
                        }
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
        });

        let start_time = std::time::Instant::now();
        while start_time.elapsed() < timeout {
            thread::sleep(Duration::from_millis(500));

            if match_count.load(Ordering::Relaxed) >= number_of_events {
                reader_handle.join().expect("reader thread panicked");

                let content = if return_log {
                    let mut file = File::open(log_path).with_context(|| "can't open log file")?;
                    let mut content = String::new();
                    file.read_to_string(&mut content)
                        .with_context(|| "can't read log file")?;
                    content
                } else {
                    String::new()
                };
                return Ok(content);
            }
        }
        cancel.store(true, Ordering::Relaxed);
        reader_handle.join().expect("reader thread panicked");
        Err(anyhow::anyhow!("timeout"))
    }

    pub fn stop(&mut self) {
        if self.bombini.exited {
            return;
        }
        self.bombini.exited = true;
        let _ = signal::kill(
            Pid::from_raw(self.bombini.process.id() as i32),
            Signal::SIGINT,
        );
        let _ = self.bombini.process.wait();
    }

    pub fn get_working_dir(&self) -> PathBuf {
        self.paths.temp_dir.path().to_path_buf()
    }
}

impl Drop for BombiniCommand {
    fn drop(&mut self) {
        self.stop();
    }
}
