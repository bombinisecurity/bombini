use std::path::PathBuf;

use tempfile::{Builder, TempDir};

pub static EXE_BOMBINI: &str = env!("CARGO_BIN_EXE_bombini");
pub static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[macro_export]
macro_rules! print_example_events {
    ($events:expr) => {
        #[cfg(feature = "examples")]
        {
            println!("{}", $events);
        }
    };
}

// Return Tmpdir, config, bpf_obj
pub fn init_test_env() -> (TempDir, PathBuf, PathBuf) {
    let mut project_dir = PathBuf::from(PROJECT_DIR);
    project_dir.pop();
    let mut config = project_dir.clone();
    config.push("config/config.yaml");
    let mut bpf_objs = project_dir.clone();
    bpf_objs.push("target/bpfel-unknown-none");
    if EXE_BOMBINI.contains("release") {
        bpf_objs.push("release");
    } else {
        bpf_objs.push("debug");
    }

    let temp_dir = Builder::new()
        .prefix("bombini-test-")
        .rand_bytes(5)
        .disable_cleanup(true)
        .tempdir()
        .expect("can't create temp dir");
    (temp_dir, config, bpf_objs)
}
