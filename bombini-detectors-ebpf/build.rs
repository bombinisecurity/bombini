use std::{path::Path, process::Command};

fn generate_bindings(shim_file: &Path, out_dir: &Path) {
    let out_file = out_dir.join("gen.rs");

    let bindings = bindgen::builder()
        .header(shim_file.to_string_lossy())
        .use_core()
        .allowlist_function("shim_.*")
        .clang_arg("-target")
        .clang_arg("bpf")
        .layout_tests(false)
        .size_t_is_usize(false)
        .disable_header_comment()
        .generate()
        .expect("failed to generate bindings from shim.c");

    std::fs::create_dir_all(out_dir).expect("failed to create co_re output directory");

    bindings
        .write_to_file(out_file)
        .expect("failed to write gen.rs");
}

/// Compile shim.c with clang to LLVM bitcode for the BPF target.
/// This produces shim.o containing the actual CO-RE relocations
/// that bpf-linker will merge into the final eBPF binary.
fn compile_shim(shim_file: &Path, out_dir: &str) {
    let status = Command::new("clang")
        .arg("-O2")
        .arg("-emit-llvm")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg("-g")
        .arg(shim_file)
        .arg("-o")
        .arg(format!("{out_dir}/shim.o"))
        .status()
        .expect("failed to execute clang — is it installed?");

    if !status.success() {
        panic!("clang failed to compile shim.c");
    }

    // Tell cargo to pass shim.o to bpf-linker
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_dir}/shim.o");
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let shim_dir = Path::new("src/co_re/c");
    let shim_file = shim_dir.join("shim.c");
    let types_file = shim_dir.join("types.h");

    generate_bindings(&shim_file, Path::new("src/co_re"));

    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "bpf" {
        compile_shim(&shim_file, &out_dir);
    }

    println!("cargo:rerun-if-changed={}", shim_file.display());
    println!("cargo:rerun-if-changed={}", types_file.display());
}
