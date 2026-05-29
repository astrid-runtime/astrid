//! Build provenance for the `astrid_build_info` metric.
//!
//! Captures the git short SHA and the `rustc` version at build time and
//! exposes them as compile-time env vars (`ASTRID_GIT_SHA`,
//! `ASTRID_RUSTC_VERSION`) that `src/metrics.rs` reads via `env!`. Both
//! fall back to `"unknown"` when the toolchain or a `.git` directory
//! isn't reachable (e.g. a source-tarball build), so `env!` never fails
//! and the metric is always populated.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let git_sha = run(Command::new("git").args(["rev-parse", "--short=12", "HEAD"]));
    println!("cargo:rustc-env=ASTRID_GIT_SHA={git_sha}");

    // Honour the toolchain cargo invoked us with rather than whatever
    // `rustc` happens to be on PATH.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = run(Command::new(rustc).arg("--version"));
    println!("cargo:rustc-env=ASTRID_RUSTC_VERSION={rustc_version}");

    // Re-run when HEAD moves so the embedded SHA tracks the checkout.
    // Best-effort: if we can't find `.git/HEAD` (worktree gitfile,
    // tarball build) the SHA simply refreshes on the next clean build.
    if let Some(head) = locate_git_head() {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}

/// Run a command and return its trimmed stdout, or `"unknown"` if it
/// fails to spawn, exits non-zero, or produces empty/non-UTF-8 output.
fn run(cmd: &mut Command) -> String {
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Walk up from the crate manifest dir to the first `.git/HEAD` file.
fn locate_git_head() -> Option<PathBuf> {
    let mut dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    loop {
        let head = dir.join(".git").join("HEAD");
        if head.is_file() {
            return Some(head);
        }
        if !dir.pop() {
            return None;
        }
    }
}
