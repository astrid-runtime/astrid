//! Build script for `astrid-capsule`.
//!
//! Two jobs:
//!
//! 1. Surface `TARGET` to the crate's runtime as an env var (existing behaviour).
//!
//! 2. Stage the WIT submodule into a layout `wasmtime::component::bindgen!`
//!    can resolve. The canonical WIT lives at `core/wit/` (a submodule of
//!    `unicity-astrid/wit`) with per-domain packages under `host/`. wasmtime's
//!    bindgen expects a single root WIT directory with one package per
//!    `deps/<name>/` subdir, so we copy each `host/<pkg>@<ver>.wit` into
//!    `wit-staging/deps/astrid-<pkg>/<pkg>@<ver>.wit`. The synthetic kernel
//!    world is supplied via the `inline:` option in `bindings.rs`.
//!
//! No external WIT packages are vendored — the host ABI is fully
//! Astrid-owned (`astrid:*` only, no `wasi:*` dependency).

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
    let host_src = wit_root.join("host");

    // Published-crate path: the `unicity-astrid/wit` submodule isn't
    // available on a consumer's machine (`cargo install astrid` pulls
    // the .crate tarball, not the workspace). The committed
    // `wit-staging/` ships with the crate; `bindings.rs` reads from
    // it directly. Skip the stage step — there's nothing to copy
    // from, and the existing committed contents are what bindgen
    // consumes.
    //
    // Workspace path: the submodule IS available; clean and re-stage
    // so the committed copy stays in lockstep with the submodule.
    // CI fails the workspace build if `git status` is dirty after
    // build.rs runs, catching drift.
    //
    // Empty-directory path: a developer who cloned without
    // `git submodule update --init` has `wit/host/` as an empty dir
    // (the submodule pointer exists but isn't checked out).
    // `host_src.exists()` returns true, but there's nothing to copy.
    // Without the .wit-file check below we'd wipe the committed
    // wit-staging and leave the working tree dirty with deletions.
    // Check for actual .wit files before deciding to re-stage.
    let has_wit_files = fs::read_dir(&host_src)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|e| e.path().extension().is_some_and(|ext| ext == "wit"))
        })
        .unwrap_or(false);
    if !has_wit_files {
        println!("cargo:rerun-if-changed=wit-staging");
        return;
    }

    let deps = staging.join("deps");

    if staging.exists() {
        fs::remove_dir_all(&staging).expect("clean wit-staging");
    }
    fs::create_dir_all(&deps).expect("create wit-staging/deps");

    fs::write(staging.join("kernel.wit"), "package kernel:placeholder;\n")
        .expect("write kernel.wit");

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
    println!("cargo:rerun-if-changed=build.rs");
    // CI environments may run `git submodule update` lazily; the
    // .gitmodules pointer changing without the working tree yet
    // checked out should still invalidate the staging dir.
    println!(
        "cargo:rerun-if-changed={}",
        crate_root
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".gitmodules")
            .display()
    );
}

fn rerun_if_dir_changed(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
}
