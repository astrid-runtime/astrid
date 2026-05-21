//! Build script for `astrid-capsule`.
//!
//! Two jobs:
//!
//! 1. Surface `TARGET` to the crate's runtime as an env var (existing behaviour).
//!
//! 2. Stage the WIT submodule into a layout `wasmtime::component::bindgen!`
//!    can resolve. The canonical WIT lives at `core/wit/` (a submodule of
//!    `unicity-astrid/wit`) with per-domain packages under `host/` and
//!    vendored dependencies under `deps/`. wasmtime's bindgen expects a
//!    single root WIT directory with one package per `deps/<name>/` subdir,
//!    so we copy each `host/<pkg>@<ver>.wit` into
//!    `wit-staging/deps/astrid-<pkg>/<pkg>@<ver>.wit`, and `wit/deps/wasi-io/`
//!    into `wit-staging/deps/wasi-io/`. The synthetic kernel world is
//!    supplied via the `inline:` option in `bindings.rs`.

use std::fs;
use std::path::Path;

fn main() {
    let target = std::env::var("TARGET").expect("TARGET environment variable not set by Cargo");
    println!("cargo:rustc-env=TARGET={target}");

    stage_wit();
}

fn stage_wit() {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wit_root = crate_root
        .parent() // crates/
        .unwrap()
        .parent() // core/
        .unwrap()
        .join("wit");

    let staging = crate_root.join("wit-staging");
    let deps = staging.join("deps");

    if staging.exists() {
        fs::remove_dir_all(&staging).expect("clean wit-staging");
    }
    fs::create_dir_all(&deps).expect("create wit-staging/deps");

    fs::write(staging.join("kernel.wit"), "package kernel:placeholder;\n")
        .expect("write kernel.wit");

    let wasi_io_src = wit_root.join("deps").join("wasi-io");
    let wasi_io_dst = deps.join("wasi-io");
    fs::create_dir_all(&wasi_io_dst).expect("mkdir deps/wasi-io");
    for entry in fs::read_dir(&wasi_io_src).expect("read wit/deps/wasi-io") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wit") {
            let dst = wasi_io_dst.join(path.file_name().unwrap());
            fs::copy(&path, &dst).expect("copy wasi-io wit");
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let host_src = wit_root.join("host");
    for entry in fs::read_dir(&host_src).expect("read wit/host") {
        let entry = entry.unwrap();
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !file_name.ends_with(".wit") {
            continue;
        }
        let stem = file_name.trim_end_matches(".wit");
        let pkg_name = stem.split('@').next().unwrap();
        let dst_dir = deps.join(format!("astrid-{pkg_name}"));
        fs::create_dir_all(&dst_dir).expect("mkdir deps/astrid-<pkg>");
        let dst = dst_dir.join(file_name);
        fs::copy(&path, &dst).expect("copy host wit");
        println!("cargo:rerun-if-changed={}", path.display());
    }

    rerun_if_dir_changed(&wit_root.join("host"));
    rerun_if_dir_changed(&wit_root.join("deps"));
    println!("cargo:rerun-if-changed=build.rs");
}

fn rerun_if_dir_changed(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
}
