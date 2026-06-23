//! `astrid capsule new <name>` — scaffold a complete, first-try-compiling
//! capsule project.
//!
//! Generates the full skeleton a tool capsule needs to build cleanly on the
//! first `cargo build`: the `.cargo/config.toml` carrying the getrandom
//! footgun fix (without it, anything pulling `getrandom` — uuid v4, the
//! `HashMap` `RandomState` — fails to *link* on `wasm32-unknown-unknown`), a
//! pinned `rust-toolchain.toml`, a `Cargo.toml` with the size-optimised
//! release profile, a `Capsule.toml` with the mandatory tool-bus ACL, a
//! working `src/lib.rs` (a `hello` tool example), and a `README.md`.
//!
//! The `wit/` directory is intentionally NOT generated — it is produced at
//! build time by `astrid capsule build`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Args;

use crate::theme::Theme;

/// Capsule kinds the scaffolder can generate. Only `tool` is supported in v1.
const SUPPORTED_KINDS: &[&str] = &["tool"];

#[derive(Args, Debug, Clone)]
pub(crate) struct NewArgs {
    /// Capsule name. Must be a valid Rust package name: lowercase letters,
    /// digits, and hyphens, starting with a letter.
    pub name: String,
    /// Capsule kind. Only `tool` is supported in v1.
    #[arg(long, default_value = "tool")]
    pub kind: String,
    /// Parent directory to create the project in. The project is written to
    /// `<path>/<name>` (defaults to `./<name>`).
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// Overwrite an existing non-empty target directory.
    #[arg(long)]
    pub force: bool,
    /// If the `wasm32-unknown-unknown` target is missing and `rustup` is
    /// available, install it without prompting (`rustup target add
    /// wasm32-unknown-unknown`). Useful in non-interactive setups.
    #[arg(long)]
    pub install_target: bool,
}

/// Entry point for `astrid capsule new`.
pub(crate) fn run(args: &NewArgs) -> Result<ExitCode> {
    if !SUPPORTED_KINDS.contains(&args.kind.as_str()) {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "unsupported capsule kind '{}'. Supported kinds: {}",
                args.kind,
                SUPPORTED_KINDS.join(", ")
            ))
        );
        return Ok(ExitCode::from(1));
    }

    if let Err(reason) = validate_name(&args.name) {
        eprintln!(
            "{}",
            Theme::error(&format!("invalid capsule name '{}': {reason}", args.name))
        );
        return Ok(ExitCode::from(1));
    }

    let parent = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let target = parent.join(&args.name);

    if dir_is_non_empty(&target) {
        if args.force {
            eprintln!(
                "{}",
                Theme::warning(&format!(
                    "overwriting existing files in {}",
                    target.display()
                ))
            );
        } else {
            eprintln!(
                "{}",
                Theme::error(&format!(
                    "target directory {} already exists and is not empty. \
                     Use --force to overwrite.",
                    target.display()
                ))
            );
            return Ok(ExitCode::from(1));
        }
    }

    // Toolchain preflight runs BEFORE we write the skeleton so any missing
    // piece is surfaced up-front. It is fail-FRIENDLY: a missing toolchain
    // only warns and guides — we still generate the project so the author has
    // something to build once they install what they need.
    preflight::check(args.install_target);

    scaffold(&target, &args.name)
        .with_context(|| format!("failed to scaffold capsule into {}", target.display()))?;

    print_next_steps(&target, &args.name);
    Ok(ExitCode::SUCCESS)
}

/// Rust-toolchain preflight: verify `cargo`/`rustc` and the
/// `wasm32-unknown-unknown` target are present, warn + guide if not, and offer
/// to install the target when `rustup` is available.
///
/// Every check is fail-FRIENDLY: nothing here aborts the scaffold. A capsule
/// author who runs `astrid capsule new` on a machine without the wasm target
/// still gets a complete, correct project — they just get told exactly what to
/// install before the first build succeeds.
mod preflight {
    use std::io::IsTerminal;
    use std::process::Command;

    use crate::theme::Theme;

    /// The compile target every capsule builds for.
    const WASM_TARGET: &str = "wasm32-unknown-unknown";

    /// Run the full preflight. `install_target` forces a non-interactive
    /// `rustup target add` when the target is missing and `rustup` is present.
    pub(super) fn check(install_target: bool) {
        // cargo / rustc presence. A missing toolchain is the only thing that
        // makes the rest moot, so report it and stop probing (but still let
        // the caller scaffold).
        let have_cargo = tool_present("cargo");
        let have_rustc = tool_present("rustc");
        if !have_cargo || !have_rustc {
            warn_no_rust_toolchain(have_cargo, have_rustc);
            return;
        }

        if wasm_target_installed() {
            return;
        }

        // Target missing. If rustup drives the toolchain we can fix it for the
        // author; otherwise we can only point at the right command.
        if rustup_present() {
            if install_target || prompt_install() {
                if run_target_add() {
                    eprintln!(
                        "{}",
                        Theme::success(&format!("installed the {WASM_TARGET} target"))
                    );
                    return;
                }
                eprintln!(
                    "{}",
                    Theme::warning(&format!(
                        "could not install the {WASM_TARGET} target automatically — \
                         run `rustup target add {WASM_TARGET}` yourself."
                    ))
                );
            } else {
                guide_rustup_target_add();
            }
        } else {
            guide_rustup_target_add();
        }
    }

    /// Whether `tool --version` runs successfully (i.e. the binary is on PATH).
    fn tool_present(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Whether `rustup` is the active toolchain manager.
    fn rustup_present() -> bool {
        tool_present("rustup")
    }

    /// Whether the wasm target's std is available to build against.
    ///
    /// Preferred probe is `rustup target list --installed` (cheap, exact). When
    /// `rustup` is not in play we fall back to asking `rustc` to emit the
    /// target cfg — that only succeeds if the target's libstd is present, so it
    /// is a reliable installed/not check for a rustup-free (e.g. distro or Nix)
    /// toolchain too.
    fn wasm_target_installed() -> bool {
        if rustup_present()
            && let Ok(out) = Command::new("rustup")
                .args(["target", "list", "--installed"])
                .output()
            && out.status.success()
        {
            return String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| line.trim() == WASM_TARGET);
        }
        // rustup absent or the query failed: probe rustc directly.
        Command::new("rustc")
            .args(["--target", WASM_TARGET, "--print", "cfg"])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Run `rustup target add wasm32-unknown-unknown`, streaming its output.
    fn run_target_add() -> bool {
        eprintln!(
            "{}",
            Theme::dimmed(&format!("running `rustup target add {WASM_TARGET}`..."))
        );
        Command::new("rustup")
            .args(["target", "add", WASM_TARGET])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Ask whether to install the missing target. Non-interactive sessions
    /// (no TTY) default to NO — we never silently mutate the toolchain without
    /// either a TTY answer or the explicit `--install-target` flag.
    fn prompt_install() -> bool {
        if !std::io::stdin().is_terminal() {
            return false;
        }
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "the {WASM_TARGET} target (required to build capsules) is not installed."
            ))
        );
        eprint!("Install it now with `rustup target add {WASM_TARGET}`? [Y/n] ");
        if std::io::Write::flush(&mut std::io::stderr()).is_err() {
            return false;
        }
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).unwrap_or(0) == 0 {
            // EOF before an answer — treat as no.
            return false;
        }
        let input = input.trim();
        input.is_empty() || input.eq_ignore_ascii_case("y") || input.eq_ignore_ascii_case("yes")
    }

    /// Print actionable guidance when the wasm target is missing and we did not
    /// (or could not) install it.
    fn guide_rustup_target_add() {
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "the {WASM_TARGET} target is not installed — capsules cannot build without it."
            ))
        );
        eprintln!("  Install it with:");
        eprintln!("    rustup target add {WASM_TARGET}");
        eprintln!(
            "{}",
            Theme::dimmed(
                "  (or pass --install-target to have `astrid capsule new` add it for you.)"
            )
        );
    }

    /// Print actionable guidance when cargo/rustc are not on PATH at all.
    fn warn_no_rust_toolchain(have_cargo: bool, have_rustc: bool) {
        let missing = match (have_cargo, have_rustc) {
            (false, false) => "cargo and rustc were",
            (false, true) => "cargo was",
            (true, false) => "rustc was",
            (true, true) => unreachable!("warn only called when one is missing"),
        };
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "{missing} not found on PATH — you need a Rust toolchain to build this capsule."
            ))
        );
        eprintln!("  Install Rust (rustup) with:");
        eprintln!("    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        eprintln!("  then add the capsule build target:");
        eprintln!("    rustup target add {WASM_TARGET}");
    }
}

/// Validate that `name` is a usable capsule + Rust package name.
///
/// Rules: lowercase ASCII letters, digits, and hyphens; must start with a
/// letter; no leading/trailing/doubled hyphens. This is the intersection of
/// what cargo accepts as a package name and what reads cleanly as a bus topic
/// segment / component id.
fn validate_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    let first = name.chars().next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return Err("name must start with a lowercase letter".into());
    }
    if name.ends_with('-') {
        return Err("name must not end with a hyphen".into());
    }
    if name.contains("--") {
        return Err("name must not contain consecutive hyphens".into());
    }
    for ch in name.chars() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            return Err(format!(
                "'{ch}' is not allowed (use lowercase letters, digits, and hyphens)"
            ));
        }
    }
    Ok(())
}

/// Whether `path` exists, is a directory, and contains at least one entry.
fn dir_is_non_empty(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

/// Write the full project skeleton into `target`.
fn scaffold(target: &Path, name: &str) -> Result<()> {
    use super::new_templates as t;

    let crate_ident = name.replace('-', "_");

    write_file(&target.join(".cargo/config.toml"), &t::cargo_config_toml())?;
    write_file(
        &target.join("rust-toolchain.toml"),
        &t::rust_toolchain_toml(),
    )?;
    write_file(&target.join("Cargo.toml"), &t::cargo_toml(name))?;
    write_file(
        &target.join("Capsule.toml"),
        &t::capsule_toml(name, &crate_ident),
    )?;
    write_file(&target.join("src/lib.rs"), &t::lib_rs())?;
    write_file(&target.join("README.md"), &t::readme_md(name))?;
    write_file(
        &target.join("AUTHORING.md"),
        &t::authoring_md(name, &crate_ident),
    )?;
    Ok(())
}

/// Write `contents` to `path`, creating parent directories as needed.
fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Print the friendly next-steps message after a successful scaffold.
fn print_next_steps(target: &Path, name: &str) {
    eprintln!(
        "{}",
        Theme::success(&format!("Created capsule '{name}' at {}", target.display()))
    );
    eprintln!();
    eprintln!("{}", Theme::header("Next steps"));
    eprintln!("  cd {}", target.display());
    eprintln!("  astrid capsule build");
    eprintln!("  astrid capsule install ./dist/{name}.capsule");
    eprintln!();
    eprintln!(
        "{}",
        Theme::dimmed("Edit src/lib.rs to replace the hello tool with your own.")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation_accepts_good_names() {
        for ok in ["a", "hello", "my-tool", "tool42", "a1-b2-c3"] {
            assert!(validate_name(ok).is_ok(), "expected '{ok}' to be valid");
        }
    }

    #[test]
    fn name_validation_rejects_bad_names() {
        for bad in [
            "",
            "1tool",
            "-tool",
            "tool-",
            "tool--name",
            "Tool",
            "my_tool",
            "my tool",
            "tool!",
        ] {
            assert!(
                validate_name(bad).is_err(),
                "expected '{bad}' to be invalid"
            );
        }
    }

    #[test]
    fn dir_is_non_empty_distinguishes_states() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        assert!(!dir_is_non_empty(&missing), "missing dir is not non-empty");

        let empty = tmp.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(!dir_is_non_empty(&empty), "empty dir is not non-empty");

        std::fs::write(empty.join("x"), "y").unwrap();
        assert!(dir_is_non_empty(&empty), "dir with a file is non-empty");
    }

    #[test]
    fn scaffold_writes_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("hello-cap");
        scaffold(&target, "hello-cap").unwrap();

        for rel in [
            ".cargo/config.toml",
            "rust-toolchain.toml",
            "Cargo.toml",
            "Capsule.toml",
            "src/lib.rs",
            "README.md",
            "AUTHORING.md",
        ] {
            assert!(
                target.join(rel).is_file(),
                "expected scaffolded file {rel} to exist"
            );
        }
    }
}
