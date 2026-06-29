//! Build provenance for the `astrid_build_info` metric.
//!
//! Captures the git short SHA and the `rustc` version at build time and
//! exposes them as compile-time env vars (`ASTRID_GIT_SHA`,
//! `ASTRID_RUSTC_VERSION`) that `src/metrics.rs` reads via `env!`. Both
//! fall back to `"unknown"` when the toolchain or a `.git` directory
//! isn't reachable (e.g. a source-tarball build), so `env!` never fails
//! and the metric is always populated.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROVENANCE_TIMEOUT: Duration = Duration::from_secs(2);

fn main() {
    let git_sha = run(Command::new("git").args(["rev-parse", "--short=12", "HEAD"]));
    println!("cargo:rustc-env=ASTRID_GIT_SHA={git_sha}");

    // Honour the toolchain cargo invoked us with rather than whatever
    // `rustc` happens to be on PATH.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = run(Command::new(rustc).arg("--version"));
    println!("cargo:rustc-env=ASTRID_RUSTC_VERSION={rustc_version}");

    // Re-run when the resolved commit changes. `.git/HEAD` is usually a
    // symbolic ref (`ref: refs/heads/<branch>`) whose *content* doesn't
    // change on a new commit — only the pointed-to ref file does — so we
    // track that file too, plus `packed-refs` as a fallback for a ref with
    // no loose file (e.g. a fresh clone). Best-effort: a tarball or worktree
    // build with no reachable `.git` simply refreshes on the next clean build.
    if let Some(head) = locate_git_head() {
        println!("cargo:rerun-if-changed={}", head.display());
        if let (Some(git_dir), Ok(contents)) = (head.parent(), std::fs::read_to_string(&head))
            && let Some(ref_path) = contents.strip_prefix("ref:")
        {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(ref_path.trim()).display()
            );
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join("packed-refs").display()
            );
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}

/// Run a command and return its trimmed stdout, or `"unknown"` if it
/// fails to spawn, exits non-zero, times out, or produces empty/non-UTF-8
/// output.
fn run(cmd: &mut Command) -> String {
    let Ok(mut child) = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return "unknown".to_string();
    };
    let deadline = Instant::now()
        .checked_add(PROVENANCE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            },
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return "unknown".to_string();
            },
            Err(_) => return "unknown".to_string(),
        }
    };
    if !status.success() {
        return "unknown".to_string();
    }

    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        use std::io::Read as _;
        let _ = pipe.read_to_end(&mut stdout);
    }
    String::from_utf8(stdout)
        .ok()
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
