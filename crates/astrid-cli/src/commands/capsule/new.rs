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

    scaffold(&target, &args.name)
        .with_context(|| format!("failed to scaffold capsule into {}", target.display()))?;

    print_next_steps(&target, &args.name);
    Ok(ExitCode::SUCCESS)
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
    let crate_ident = name.replace('-', "_");

    write_file(&target.join(".cargo/config.toml"), &cargo_config_toml())?;
    write_file(&target.join("rust-toolchain.toml"), &rust_toolchain_toml())?;
    write_file(&target.join("Cargo.toml"), &cargo_toml(name))?;
    write_file(
        &target.join("Capsule.toml"),
        &capsule_toml(name, &crate_ident),
    )?;
    write_file(&target.join("src/lib.rs"), &lib_rs())?;
    write_file(&target.join("README.md"), &readme_md(name))?;
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

/// `.cargo/config.toml` — the getrandom footgun fix. Without the custom
/// backend cfg, `getrandom` (pulled transitively by uuid v4 and `HashMap`'s
/// `RandomState`) fails to link on `wasm32-unknown-unknown`.
fn cargo_config_toml() -> String {
    r#"[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = ["--cfg=getrandom_backend=\"custom\""]
"#
    .to_string()
}

/// `rust-toolchain.toml` — pins the toolchain and wasm target so the project
/// builds identically everywhere.
fn rust_toolchain_toml() -> String {
    r#"[toolchain]
channel = "1.94.0"
targets = ["wasm32-unknown-unknown"]
components = ["rustfmt", "clippy"]
"#
    .to_string()
}

/// `Cargo.toml` — `cdylib` for the WASM component, edition 2024, and a
/// size-optimised release profile.
fn cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
publish = false
description = "An Astrid tool capsule."

[lib]
crate-type = ["cdylib"]

[dependencies]
astrid-sdk = {{ version = "0.7", features = ["derive"] }}
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
"#
    )
}

/// `Capsule.toml` — manifest with the `[[component]]` block and the mandatory
/// tool-bus ACL. The `[publish]`/`[subscribe]` tables are the only IPC-intent
/// surface; a `[subscribe]` entry's `handler` binds the topic to the matching
/// `#[astrid::tool]` / `tool_describe` export.
fn capsule_toml(name: &str, crate_ident: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
description = "An Astrid tool capsule."
astrid-version = ">=0.7.0"

[[component]]
id = "{name}"
file = "{crate_ident}.wasm"
type = "executable"

# Host capabilities this capsule needs. The hello example needs none. Grant
# only what your tools actually use — capabilities are enforced by the kernel.
#
# [capabilities]
# fs_read  = ["home://"]
# fs_write = ["home://output/"]

# Publish ACL: the [publish] keys are the only IPC-publish declaration.
[publish]
"tool.v1.execute.*.result" = {{ wit = "@unicity-astrid/wit/types/tool-call-result" }}
"tool.v1.response.describe.*" = {{ wit = "@unicity-astrid/wit/tool/describe-response" }}

# Interceptor bindings: a [subscribe] entry's `handler` binds the topic to an
# `#[astrid::tool]` export. The keys also serve as the subscribe ACL.
[subscribe]
"tool.v1.execute.hello" = {{ wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_hello" }}
"tool.v1.request.describe" = {{ wit = "@unicity-astrid/wit/tool/describe-request", handler = "tool_describe" }}
"#
    )
}

/// `src/lib.rs` — a working `hello` tool example.
fn lib_rs() -> String {
    r#"#![deny(unsafe_code)]
use astrid_sdk::prelude::*;
use astrid_sdk::schemars;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct HelloArgs {
    /// Who to greet.
    pub name: String,
}

#[derive(Default)]
pub struct Capsule;

#[capsule]
impl Capsule {
    /// Greet someone by name. Replace this with your own tool.
    #[astrid::tool("hello")]
    pub fn hello(&self, args: HelloArgs) -> Result<String, SysError> {
        Ok(format!("Hello, {}!", args.name.trim()))
    }
}
"#
    .to_string()
}

/// `README.md` for the generated project: build/install/iterate commands and
/// pointers to the in-runtime skill and the Astrid Book.
fn readme_md(name: &str) -> String {
    format!(
        r#"# {name}

An [Astrid](https://github.com/unicity-astrid/astrid) tool capsule, scaffolded
by `astrid capsule new`.

A capsule is a WebAssembly component that runs in the Astrid kernel's sandbox
and exposes typed tools to the agent. This one ships a single `hello` tool —
replace it with your own.

## Layout

| File | Purpose |
|------|---------|
| `src/lib.rs` | Tool implementations (`#[astrid::tool]` exports). |
| `Capsule.toml` | Manifest: component, capabilities, and the tool-bus ACL. |
| `Cargo.toml` | Crate config — `cdylib` + size-optimised release profile. |
| `.cargo/config.toml` | Targets `wasm32-unknown-unknown` and sets the `getrandom` custom backend (required — without it, uuid/`HashMap` fail to link). |
| `rust-toolchain.toml` | Pins the toolchain and wasm target. |

The `wit/` directory is generated at build time; do not commit it.

## Build

```sh
astrid capsule build
```

This compiles to `wasm32-unknown-unknown` and packages a `.capsule` archive
under `dist/`.

## Install

```sh
astrid capsule install ./dist/{name}.capsule
```

## Iterate

1. Edit `src/lib.rs` — add a tool with `#[astrid::tool("my_tool")]`.
2. Declare it in `Capsule.toml` under `[subscribe]`:
   ```toml
   "tool.v1.execute.my_tool" = {{ wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_my_tool" }}
   ```
3. Rebuild and reinstall.

## Learn more

- If the `capsule-forge` capsule is installed, its authoring skill — the
  from-zero guide to writing capsules — lives at
  `home://skills/capsule-forge/SKILL.md`.
- The [Astrid Book](https://github.com/unicity-astrid/astrid) covers the
  capsule model, the IPC bus, capabilities, and the WIT contracts in depth.
"#
    )
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
        ] {
            assert!(
                target.join(rel).is_file(),
                "expected scaffolded file {rel} to exist"
            );
        }
    }

    #[test]
    fn cargo_config_has_getrandom_backend() {
        let cfg = cargo_config_toml();
        assert!(
            cfg.contains(r#"getrandom_backend=\"custom\""#),
            "getrandom custom backend cfg is mandatory for wasm linking"
        );
        assert!(cfg.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn cargo_toml_uses_crate_name_and_cdylib() {
        let toml = cargo_toml("my-tool");
        assert!(toml.contains(r#"name = "my-tool""#));
        assert!(toml.contains(r#"crate-type = ["cdylib"]"#));
        assert!(toml.contains(r#"edition = "2024""#));
        assert!(toml.contains("panic = \"abort\""));
        // Must parse as TOML.
        toml.parse::<toml::Value>().expect("Cargo.toml must parse");
    }

    #[test]
    fn capsule_toml_wasm_file_uses_underscored_ident() {
        // The component `file` must be the crate ident (hyphens → underscores)
        // plus `.wasm`, matching cargo's cdylib output name.
        let manifest = capsule_toml("my-tool", "my_tool");
        assert!(
            manifest.contains(r#"file = "my_tool.wasm""#),
            "wasm filename must use the underscored crate ident"
        );
        assert!(manifest.contains(r#"id = "my-tool""#));
    }

    #[test]
    fn capsule_toml_parses_and_has_tool_acl() {
        let manifest = capsule_toml("hello-cap", "hello_cap");
        let value: toml::Value = manifest.parse().expect("Capsule.toml must parse");

        // Package block.
        assert_eq!(value["package"]["name"].as_str(), Some("hello-cap"));
        assert_eq!(value["package"]["version"].as_str(), Some("0.1.0"));

        // Component block.
        let component = &value["component"][0];
        assert_eq!(component["id"].as_str(), Some("hello-cap"));
        assert_eq!(component["type"].as_str(), Some("executable"));

        // Tool-bus ACL: the hello tool + describe must be subscribed with
        // their handlers, and results/describe responses publishable.
        let subscribe = value["subscribe"].as_table().expect("subscribe table");
        let hello = subscribe["tool.v1.execute.hello"]
            .as_table()
            .expect("hello subscribe entry");
        assert_eq!(hello["handler"].as_str(), Some("tool_execute_hello"));
        let describe = subscribe["tool.v1.request.describe"]
            .as_table()
            .expect("describe subscribe entry");
        assert_eq!(describe["handler"].as_str(), Some("tool_describe"));

        let publish = value["publish"].as_table().expect("publish table");
        assert!(publish.contains_key("tool.v1.execute.*.result"));
        assert!(publish.contains_key("tool.v1.response.describe.*"));
    }

    #[test]
    fn lib_rs_has_hello_tool() {
        let src = lib_rs();
        assert!(src.contains(r#"#[astrid::tool("hello")]"#));
        assert!(src.contains("pub fn hello"));
        assert!(src.contains("#[capsule]"));
    }
}
