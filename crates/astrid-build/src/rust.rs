//! Rust capsule builder — compiles a Rust crate to `wasm32-wasip2` and packages it.
use crate::archiver::{discover_opaque_assets, pack_capsule_archive};
use anyhow::{Context, Result, bail};
use cargo_metadata::{Message, PackageId};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{info, warn};

mod config;
#[cfg(test)]
use config::{
    cargo_config_has_matching_target_rustflags_with_home,
    cargo_config_rustflags_for_target_with_home,
    cargo_config_target_and_rustflags_for_target_with_home,
    cargo_config_target_and_rustflags_with_home, resolve_cargo_home,
};
use config::{cargo_config_rustflags_for_target, cargo_config_target_and_rustflags};

/// Stub WIT package written when a capsule has no local `wit/` directory.
/// Gives `push_dir` a main package to anchor on so deps can still be loaded.
const STUB_WIT_PACKAGE: &str = "package astrid:capsule-stub@1.0.0;\n\ninterface stub {}\n";

/// The only capsule target that needs the getrandom cfg injected. Other
/// targets get a real platform backend from their runtime: `wasm32-wasip2`
/// from WASI, and native build-script / proc-macro units from the host OS.
const GETRANDOM_TARGET: &str = "wasm32-unknown-unknown";

/// The `getrandom` custom-backend cfg every `wasm32-unknown-unknown` capsule
/// needs so that `uuid` v4 / `HashMap` seeding link against `astrid-sys`'s
/// host-routed RNG (`astrid:sys/host.random-bytes`) instead of failing with
/// getrandom's "wasm32-unknown-unknown is not supported by default"
/// `compile_error!`. Injecting it here means `astrid build` succeeds even
/// when a capsule's `.cargo/config.toml` is missing the flag — capsules still
/// keep it in config for plain `cargo build` / `cargo test`, which don't run
/// through this builder.
const GETRANDOM_CUSTOM_CFG: &str = "--cfg=getrandom_backend=\"custom\"";
const GETRANDOM_CARGO_CONFIG_TARGET: &str = "target.'cfg(all(target_arch = \"wasm32\", target_os = \"unknown\", target_env = \"\", target_pointer_width = \"32\", target_vendor = \"unknown\", target_family = \"wasm\"))'.rustflags=";

/// Cargo's argument separator for `CARGO_ENCODED_RUSTFLAGS` (ASCII unit
/// separator). Keeping it as a string allows direct concatenation without an
/// intermediate character allocation.
const RUSTFLAGS_SEP: &str = "\u{1f}";

/// Build a Rust capsule from a crate directory.
///
/// 1. `cargo build --release` using Cargo's resolved target/configuration
/// 2. Extract capsule description via Extism (`astrid_export_schemas`)
/// 3. Merge description into `Capsule.toml`
/// 4. Pack into `.capsule` archive
pub(crate) fn build(dir: &Path, output: Option<&str>) -> Result<()> {
    info!("Building Rust WASM capsule from {}", dir.display());

    verify_cargo_available()?;

    let (meta, crate_name, package_version, wasm_name, package_id) = resolve_package_metadata(dir)?;

    let compiled = compile_wasm(dir, &package_id, &wasm_name)?;

    let wasm_path = locate_wasm_binary(&meta, &compiled.target, &wasm_name)?;
    if wasm_path != compiled.path {
        bail!(
            "Cargo reported compiled WASM at {}, but the exact release artifact is {}",
            compiled.path.display(),
            wasm_path.display()
        );
    }
    let wasm_path = ensure_component(&wasm_path)?;

    let toml_content =
        build_manifest_content(dir, &wasm_path, &crate_name, &package_version, &wasm_name)?;
    let assets = discover_opaque_assets(dir)?;
    let asset_refs: Vec<&Path> = assets.iter().map(PathBuf::as_path).collect();

    let out_dir = resolve_output_dir(output)?;
    let out_file = out_dir.join(format!("{crate_name}.capsule"));

    // Stage the wit/ directory — merges the capsule's own wit/ (if any) with
    // the astrid-sdk shared contracts as a WIT dependency so capsule authors
    // can reference shared records via `wit_type` without duplication.
    let wit_staging = stage_wit_directory(dir, &meta)?;

    pack_capsule_archive(
        &out_file,
        &toml_content,
        Some(&wasm_path),
        dir,
        &asset_refs,
        wit_staging.as_deref(),
    )?;
    crate::artifact::sign_archive_with_runtime_key(&out_file)?;

    info!("Successfully built Rust capsule: {}", out_file.display());
    Ok(())
}

/// Verify that `cargo` is installed and available on PATH.
fn verify_cargo_available() -> Result<()> {
    if std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .is_err()
    {
        bail!("`cargo` is not installed or not in PATH. Rust compilation failed.");
    }
    Ok(())
}

/// Resolve package metadata for the crate in `dir`.
fn resolve_package_metadata(
    dir: &Path,
) -> Result<(cargo_metadata::Metadata, String, String, String, PackageId)> {
    // Resolve the full dependency graph (not no_deps) so we can locate
    // the astrid-sdk source directory for WIT file bundling.
    let meta = cargo_metadata::MetadataCommand::new()
        .current_dir(dir)
        .exec()
        .context("Failed to parse Cargo metadata")?;

    let package = meta
        .packages
        .iter()
        .find(|p| {
            if let Some(parent) = p.manifest_path.parent()
                && let Ok(canon_parent) = parent.as_std_path().canonicalize()
                && let Ok(canon_dir) = dir.canonicalize()
            {
                return canon_parent == canon_dir;
            }
            false
        })
        .or_else(|| meta.root_package())
        .context("No package found matching the target directory in Cargo.toml")?;

    let crate_name = package.name.to_string();
    let package_version = package.version.to_string();
    let wasm_name = resolve_wasm_output_name(package)?;
    let package_id = package.id.clone();

    Ok((meta, crate_name, package_version, wasm_name, package_id))
}

/// Resolve the exact WASM file stem Cargo will use for the capsule.
///
/// Capsules are packaged from a single cdylib target. Cargo metadata reports
/// the target's output name, which matters when a manifest gives the library
/// an explicit name instead of using the package name. A package without a
/// cdylib target cannot produce the artifact this builder packages, so it is
/// rejected rather than guessing a same-named binary.
fn resolve_wasm_output_name(package: &cargo_metadata::Package) -> Result<String> {
    resolve_wasm_output_name_from_targets(
        package
            .targets
            .iter()
            .filter(|target| target.is_cdylib())
            .map(|target| target.name.clone()),
    )
}

fn resolve_wasm_output_name_from_targets<I>(output_names: I) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let output_names: Vec<String> = output_names.into_iter().collect();
    match output_names.as_slice() {
        [] => bail!("Capsule has no cdylib target; refusing to guess a WASM artifact"),
        [output_name] => validate_wasm_output_name(output_name),
        _ => bail!(
            "Capsule has {} cdylib targets; refusing to choose an ambiguous WASM artifact",
            output_names.len()
        ),
    }
}

fn validate_wasm_output_name(output_name: &str) -> Result<String> {
    let path = Path::new(output_name);
    let is_single_normal_component =
        output_name != "." && output_name != ".." && path.file_name() == Some(path.as_os_str());
    if !is_single_normal_component {
        bail!("Unsafe WASM artifact name: {output_name}");
    }
    Ok(output_name.to_owned())
}

/// Compile the capsule in release mode using whatever target Cargo resolves
/// from its complete configuration hierarchy.
///
/// The Astrid-canonical target is `wasm32-unknown-unknown` — zero
/// `wasi:*` imports, every host call audited through the
/// `astrid:*` SDK surface. Capsules may also target `wasm32-wasip2`
/// during the migration window (the kernel still satisfies wasi:*
/// for backwards compatibility), so this build step does NOT pass
/// `--target`; it lets Cargo's own config and environment precedence decide.
///
/// When the capsule targets `wasm32-unknown-unknown` it additionally
/// injects the getrandom custom-backend cfg through target-wide rustflags so
/// `astrid build` succeeds even when a capsule's `.cargo/config.toml` is
/// missing `--cfg=getrandom_backend="custom"`. This is a safety net for the
/// canonical build tool, not a replacement: capsules still carry the flag
/// in config so a plain `cargo build` / `cargo test` (which never runs
/// through here) keeps linking `uuid` v4 / `HashMap`.
struct CompiledWasm {
    target: String,
    path: PathBuf,
}

fn compile_wasm(dir: &Path, package_id: &PackageId, wasm_name: &str) -> Result<CompiledWasm> {
    let (config_target, _) = cargo_config_target_and_rustflags(dir)?;
    // `CARGO_BUILD_TARGET` (if the caller set it) overrides the config-file
    // target, mirroring Cargo's own precedence.
    let env_target = std::env::var("CARGO_BUILD_TARGET")
        .ok()
        .filter(|target| !target.trim().is_empty());
    let target = resolve_build_target(config_target, env_target)?;
    let (config_flags, has_matching_target_rustflags) = if inject_getrandom_for_target(&target) {
        cargo_config_rustflags_for_target(dir, &target)?
    } else {
        (Vec::new(), false)
    };
    let rustflags = RustflagsEnvironment::from_process(&target);
    compile_wasm_with_target(
        dir,
        package_id,
        wasm_name,
        target,
        &config_flags,
        has_matching_target_rustflags,
        &rustflags,
    )
}

fn compile_wasm_with_target(
    dir: &Path,
    package_id: &PackageId,
    wasm_name: &str,
    target: String,
    config_flags: &[String],
    has_matching_target_rustflags: bool,
    rustflags: &RustflagsEnvironment,
) -> Result<CompiledWasm> {
    info!("   Compiling capsule (release)...");

    // Cargo itself remains authoritative for the build. For the one target
    // that needs Astrid's custom getrandom backend, append the cfg to the
    // highest-precedence environment source or use a Cargo config override;
    // both reach dependencies as well as the root cdylib.
    let inject_getrandom_cfg = inject_getrandom_for_target(&target);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir)
        .args([
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    rustflags.configure_command(&mut cmd, &target);
    if inject_getrandom_cfg {
        append_getrandom_rustflag(
            &mut cmd,
            &target,
            has_matching_target_rustflags,
            config_flags,
            rustflags,
        );
    }

    let mut child = cmd.spawn().context("Failed to spawn cargo build")?;
    let stdout = child
        .stdout
        .take()
        .context("Cargo build did not expose machine-readable output")?;
    let expected_filename = format!("{wasm_name}.wasm");
    let mut artifacts = Vec::new();
    for message in Message::parse_stream(BufReader::new(stdout)) {
        let message = message.context("Failed to parse Cargo build output")?;
        let Message::CompilerArtifact(artifact) = message else {
            continue;
        };
        if artifact.package_id != *package_id
            || !artifact.target.is_cdylib()
            || artifact.profile.test
        {
            continue;
        }
        artifacts.extend(
            artifact
                .filenames
                .into_iter()
                .filter(|path| {
                    path.file_name()
                        .is_some_and(|name| name == expected_filename)
                })
                .map(cargo_metadata::camino::Utf8PathBuf::into_std_path_buf),
        );
    }

    let status = child.wait().context("Failed to wait for cargo build")?;

    if !status.success() {
        bail!(
            "Cargo build failed. Set `[build] target = \"wasm32-unknown-unknown\"` (Astrid-canonical) or `wasm32-wasip2` in `.cargo/config.toml` and install the matching `rustup target` component."
        );
    }

    artifacts.sort();
    artifacts.dedup();
    match artifacts.as_slice() {
        [path] => Ok(CompiledWasm {
            target,
            path: path.clone(),
        }),
        [] => bail!(
            "Cargo completed without emitting the exact release cdylib artifact {expected_filename}"
        ),
        _ => bail!(
            "Cargo emitted {} release cdylib artifacts named {expected_filename}; refusing to choose an ambiguous artifact",
            artifacts.len()
        ),
    }
}

fn inject_getrandom_for_target(target: &str) -> bool {
    target == GETRANDOM_TARGET
}

/// Append the custom getrandom cfg without replacing any effective Cargo
/// rustflags. Cargo's precedence is encoded-rustflags env, plain rustflags env,
/// target-specific rustflags env, matching target config, then build
/// rustflags. We modify only the first effective environment source. When
/// config-derived flags are effective (including when `CARGO_BUILD_RUSTFLAGS`
/// is shadowed by matching target entries), a Cargo config override preserves
/// Cargo's own hierarchy and reaches every dependency.
fn append_getrandom_rustflag(
    cmd: &mut Command,
    target: &str,
    has_matching_target_rustflags: bool,
    config_flags: &[String],
    rustflags: &RustflagsEnvironment,
) {
    let Some((key, value)) = getrandom_rustflags_override(
        target,
        config_flags,
        rustflags.encoded.as_deref(),
        rustflags.plain.as_deref(),
        rustflags.target_specific.as_deref(),
        rustflags.build.as_deref(),
    ) else {
        return;
    };
    if rustflags.encoded.is_none()
        && rustflags.plain.is_none()
        && rustflags.target_specific.is_none()
        && (rustflags.build.is_none() || has_matching_target_rustflags)
    {
        if has_matching_target_rustflags {
            // Let Cargo merge all matching target triples and cfg expressions,
            // ancestor arrays, and its own config precedence before adding
            // ours. Matching target entries already shadow build rustflags;
            // preserving them here avoids changing that precedence.
            let config = cargo_config_with_getrandom(&[]);
            cmd.args(["--config", config.as_str()]);
        } else {
            // A target-specific override shadows `[build].rustflags`, so
            // carry the effective build flags into the override before adding
            // the backend cfg. Otherwise the builder silently drops caller
            // flags for every dependency and the root cdylib alike.
            let config = cargo_config_with_getrandom(config_flags);
            cmd.args(["--config", config.as_str()]);
        }
    } else {
        cmd.env(key, value);
    }
}

fn cargo_config_with_getrandom(config_flags: &[String]) -> String {
    let mut flags = toml_edit::Array::new();
    for flag in config_flags {
        flags.push(flag.as_str());
    }
    if !config_flags.iter().any(|flag| flag == GETRANDOM_CUSTOM_CFG) {
        flags.push(GETRANDOM_CUSTOM_CFG);
    }
    format!("{GETRANDOM_CARGO_CONFIG_TARGET}{flags}")
}

#[derive(Default)]
struct RustflagsEnvironment {
    encoded: Option<String>,
    plain: Option<String>,
    target_specific: Option<String>,
    build: Option<String>,
}

impl RustflagsEnvironment {
    fn from_process(target: &str) -> Self {
        let target_env_key = cargo_target_rustflags_env_key(target);
        Self {
            encoded: std::env::var("CARGO_ENCODED_RUSTFLAGS").ok(),
            plain: std::env::var("RUSTFLAGS").ok(),
            target_specific: std::env::var(target_env_key).ok(),
            build: std::env::var("CARGO_BUILD_RUSTFLAGS").ok(),
        }
    }

    fn configure_command(&self, cmd: &mut Command, target: &str) {
        let target_env_key = cargo_target_rustflags_env_key(target);
        configure_env(cmd, "CARGO_ENCODED_RUSTFLAGS", self.encoded.as_deref());
        configure_env(cmd, "RUSTFLAGS", self.plain.as_deref());
        configure_env(cmd, &target_env_key, self.target_specific.as_deref());
        configure_env(cmd, "CARGO_BUILD_RUSTFLAGS", self.build.as_deref());
    }
}

fn configure_env(cmd: &mut Command, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        cmd.env(key, value);
    } else {
        cmd.env_remove(key);
    }
}

fn cargo_target_rustflags_env_key(target: &str) -> String {
    let normalized = target
        .chars()
        .map(|character| match character {
            '-' | '.' => '_',
            character => character.to_ascii_uppercase(),
        })
        .collect::<String>();
    format!("CARGO_TARGET_{normalized}_RUSTFLAGS")
}

fn getrandom_rustflags_override(
    target: &str,
    config_flags: &[String],
    encoded: Option<&str>,
    plain: Option<&str>,
    target_specific: Option<&str>,
    build_env: Option<&str>,
) -> Option<(String, String)> {
    if target != GETRANDOM_TARGET {
        return None;
    }

    if let Some(encoded) = encoded {
        let value = if encoded
            .split(RUSTFLAGS_SEP)
            .any(|flag| flag == GETRANDOM_CUSTOM_CFG)
        {
            encoded.to_owned()
        } else {
            let mut value = encoded.to_owned();
            if !value.is_empty() {
                value.push_str(RUSTFLAGS_SEP);
            }
            value.push_str(GETRANDOM_CUSTOM_CFG);
            value
        };
        return Some(("CARGO_ENCODED_RUSTFLAGS".to_owned(), value));
    }
    if let Some(plain) = plain {
        let value = if plain
            .split_whitespace()
            .any(|flag| flag == GETRANDOM_CUSTOM_CFG)
        {
            plain.to_owned()
        } else {
            let mut value = plain.to_owned();
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(GETRANDOM_CUSTOM_CFG);
            value
        };
        return Some(("RUSTFLAGS".to_owned(), value));
    }

    let key = cargo_target_rustflags_env_key(target);
    if let Some(target_specific) = target_specific {
        let value = if target_specific
            .split_whitespace()
            .any(|flag| flag == GETRANDOM_CUSTOM_CFG)
        {
            target_specific.to_owned()
        } else {
            let mut value = target_specific.to_owned();
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(GETRANDOM_CUSTOM_CFG);
            value
        };
        return Some((key, value));
    }

    if let Some(build_env) = build_env {
        let value = if build_env
            .split_whitespace()
            .any(|flag| flag == GETRANDOM_CUSTOM_CFG)
        {
            build_env.to_owned()
        } else {
            let mut value = build_env.to_owned();
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(GETRANDOM_CUSTOM_CFG);
            value
        };
        return Some(("CARGO_BUILD_RUSTFLAGS".to_owned(), value));
    }

    if config_flags.iter().any(|flag| flag == GETRANDOM_CUSTOM_CFG) {
        return Some((
            "CARGO_ENCODED_RUSTFLAGS".to_owned(),
            config_flags.join(RUSTFLAGS_SEP),
        ));
    }

    let mut value = config_flags.join(RUSTFLAGS_SEP);
    if !value.is_empty() {
        value.push_str(RUSTFLAGS_SEP);
    }
    value.push_str(GETRANDOM_CUSTOM_CFG);
    Some(("CARGO_ENCODED_RUSTFLAGS".to_owned(), value))
}

fn resolve_build_target(
    config_target: Option<String>,
    env_target: Option<String>,
) -> Result<String> {
    env_target
        .or(config_target)
        .filter(|target| !target.trim().is_empty())
        .ok_or_else(|| {
        anyhow::anyhow!(
            "No Cargo build target selected. Set `[build] target = \"wasm32-unknown-unknown\"` (Astrid-canonical) or `wasm32-wasip2` in `.cargo/config.toml`, or set CARGO_BUILD_TARGET."
        )
    })
}

/// Wrap a core wasm module into a Component Model component if it isn't
/// one already. `wasm32-unknown-unknown` (Astrid-canonical) produces a
/// core module with `wit-bindgen`'s component-type custom section
/// embedded; `wit_component::ComponentEncoder` consumes that section and
/// emits a real component. `wasm32-wasip2` builds skip this — cargo
/// already produces a component there.
fn ensure_component(wasm_path: &Path) -> Result<PathBuf> {
    let bytes =
        std::fs::read(wasm_path).context("Failed to read compiled WASM for component check")?;
    // Component magic: \0asm version=0x0d layer=0x01. Core magic:
    // \0asm version=0x01. The 4-byte version field at offset 4
    // distinguishes them.
    let is_component = bytes.len() >= 8 && &bytes[..4] == b"\0asm" && bytes[6] == 0x01;
    if is_component {
        return Ok(wasm_path.to_path_buf());
    }
    info!("   Wrapping core wasm into Component Model component...");
    let mut encoder = wit_component::ComponentEncoder::default();
    let component = encoder
        .validate(true)
        .module(&bytes)
        .context("ComponentEncoder rejected the core wasm — wit-bindgen `generate!` may be missing or producing the wrong section")?
        .encode()
        .context("ComponentEncoder failed to emit a component")?;
    // Overwrite the original artifact path so the capsule's
    // `Capsule.toml [[component]] file = "<packaged-basename>.wasm"` directive
    // continues to resolve. Using a `.component.wasm` sibling instead
    // would force every capsule manifest to track which target produced
    // the artifact — that's friction the toolchain should hide.
    std::fs::write(wasm_path, component).with_context(|| {
        format!(
            "Failed to write wrapped component to {}",
            wasm_path.display()
        )
    })?;
    Ok(wasm_path.to_path_buf())
}

/// Locate the compiled WASM binary in Cargo's resolved target directory.
///
/// The guest target is known from the same precedence used to invoke Cargo,
/// and the artifact is the exact package cdylib built for the release
/// profile. There is deliberately no recursive search or local-target
/// fallback: probing other roots could select stale artifacts when a
/// host-wide target root is configured.
fn locate_wasm_binary(
    meta: &cargo_metadata::Metadata,
    target: &str,
    wasm_name: &str,
) -> Result<PathBuf> {
    const PROFILE: &str = "release";
    let target_root = meta.target_directory.as_std_path();
    validate_wasm_output_name(wasm_name)?;

    let candidate = target_root
        .join(target)
        .join(PROFILE)
        .join(format!("{wasm_name}.wasm"));
    let artifact_metadata = match fs::symlink_metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
            "Could not locate compiled WASM binary at `target/{target}/{PROFILE}/{wasm_name}.wasm` under configured target directory {}",
            target_root.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to inspect compiled WASM binary {}",
                    candidate.display()
                )
            });
        },
    };

    if artifact_metadata.file_type().is_symlink() {
        bail!("Compiled WASM binary is a symlink: {}", candidate.display());
    }
    if !artifact_metadata.is_file() {
        bail!(
            "Compiled WASM binary is not a regular file: {}",
            candidate.display()
        );
    }

    // A regular artifact beneath a symlinked parent could still resolve
    // outside the configured root. Canonicalize only for containment; return
    // Cargo's path so callers retain the authoritative configured location,
    // including when the target root itself is a legitimate symlink.
    let resolved_target_root = fs::canonicalize(target_root).with_context(|| {
        format!(
            "Failed to resolve target directory {}",
            target_root.display()
        )
    })?;
    let resolved_candidate = fs::canonicalize(&candidate).with_context(|| {
        format!(
            "Failed to resolve compiled WASM binary {}",
            candidate.display()
        )
    })?;
    if !resolved_candidate.starts_with(&resolved_target_root) {
        bail!(
            "Compiled WASM binary {} escapes configured target directory {}",
            candidate.display(),
            target_root.display()
        );
    }

    Ok(candidate)
}

/// Merge the developer's `Capsule.toml` with any extracted description.
fn build_manifest_content(
    dir: &Path,
    wasm_path: &Path,
    crate_name: &str,
    package_version: &str,
    wasm_name: &str,
) -> Result<String> {
    let capsule_description = extract_capsule_description(wasm_path);
    let packaged_name = format!("{wasm_name}.wasm");

    let base_toml_path = dir.join("Capsule.toml");
    let mut toml_doc = if base_toml_path.exists() {
        let content = fs::read_to_string(&base_toml_path).context("Failed to read Capsule.toml")?;
        content
            .parse::<toml_edit::DocumentMut>()
            .context("Failed to parse Capsule.toml")?
    } else {
        create_default_manifest(crate_name, package_version, wasm_name)
    };

    bind_manifest_to_packaged_wasm(&mut toml_doc, &packaged_name)?;

    if let Some(desc) = &capsule_description
        && let Some(pkg) = toml_doc.get_mut("package")
        && let Some(table) = pkg.as_table_mut()
    {
        let existing = table
            .get("description")
            .and_then(toml_edit::Item::as_str)
            .unwrap_or("");
        if existing.is_empty() {
            table.insert("description", toml_edit::value(desc.as_str()));
        }
    }

    Ok(toml_doc.to_string())
}

/// Bind the manifest's single WASM component to the one file the archiver
/// writes. A hand-authored manifest can retain an old package-name filename
/// after a `[lib] name = "..."` change; leaving that pointer untouched would
/// produce an archive whose executable cannot be resolved at install time.
///
/// This builder emits exactly one cdylib, so multiple component tables are an
/// unsafe ambiguity rather than an invitation to discard author-declared
/// components. All other component fields (id, type, hash, links, and
/// capabilities) remain untouched. If an author supplied both `file` and the
/// legacy `entrypoint` alias, fail closed instead of choosing one silently.
fn bind_manifest_to_packaged_wasm(
    toml_doc: &mut toml_edit::DocumentMut,
    packaged_name: &str,
) -> Result<()> {
    validate_wasm_output_name(packaged_name.strip_suffix(".wasm").unwrap_or(packaged_name))?;

    let Some(component_item) = toml_doc.get_mut("component") else {
        let mut component = toml_edit::Table::new();
        let component_id = packaged_name.strip_suffix(".wasm").unwrap_or(packaged_name);
        component.insert("id", toml_edit::value(component_id));
        component.insert("file", toml_edit::value(packaged_name));
        component.insert("type", toml_edit::value("executable"));
        let mut components = toml_edit::ArrayOfTables::new();
        components.push(component);
        toml_doc.insert("component", toml_edit::Item::ArrayOfTables(components));
        return Ok(());
    };

    let Some(components) = component_item.as_array_of_tables_mut() else {
        bail!("Capsule.toml component must be an array of tables")
    };
    if components.len() != 1 {
        bail!(
            "Capsule.toml declares {} components, but this build packages exactly one cdylib",
            components.len()
        );
    }
    let component = components
        .get_mut(0)
        .context("Capsule.toml component array unexpectedly empty")?;
    let has_file = component.get("file").is_some();
    let has_entrypoint = component.get("entrypoint").is_some();
    if has_file && has_entrypoint {
        bail!(
            "Capsule.toml component declares both `file` and `entrypoint`; refusing an ambiguous executable path"
        );
    }

    let key = if has_file {
        "file"
    } else if has_entrypoint {
        "entrypoint"
    } else {
        "file"
    };
    if let Some(item) = component.get(key)
        && item.as_str().is_none()
    {
        bail!("Capsule.toml component `{key}` must be a string")
    }
    component.insert(key, toml_edit::value(packaged_name));
    Ok(())
}

/// Resolve the output directory, creating it if necessary.
fn resolve_output_dir(output: Option<&str>) -> Result<PathBuf> {
    let out_dir = match output {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()?.join("dist"),
    };
    if !out_dir.exists() {
        fs::create_dir_all(&out_dir)?;
    }
    Ok(out_dir)
}

/// Stage a `wit/` directory for inclusion in the capsule archive.
///
/// Returns `Some(path)` to a temp directory containing the merged WIT files,
/// or `None` if no WIT content should be bundled (e.g. SDK not resolvable
/// and no local wit/).
///
/// Layout produced:
/// ```text
/// <staging>/
///   [capsule.wit or events.wit]    ← capsule's own package, or stub
///   deps/
///     astrid-contracts/
///       astrid-contracts.wit       ← shared SDK contracts
/// ```
fn stage_wit_directory(
    capsule_dir: &Path,
    meta: &cargo_metadata::Metadata,
) -> Result<Option<PathBuf>> {
    let sdk_contracts = find_sdk_contracts_wit(meta);

    // If the capsule has neither its own wit/ nor we can find shared SDK
    // contracts, there's nothing to stage.
    let capsule_wit = capsule_dir.join("wit");
    if !capsule_wit.is_dir() && sdk_contracts.is_none() {
        return Ok(None);
    }

    // Stage under the resolved target directory so it works in workspaces
    // and gets cleaned by `cargo clean`.
    let staging = meta
        .target_directory
        .as_std_path()
        .join(".astrid-wit-staging");
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("failed to clean staging dir: {}", staging.display()))?;
    }
    fs::create_dir_all(&staging)
        .with_context(|| format!("failed to create staging dir: {}", staging.display()))?;

    // 1. Copy the capsule's own wit/ contents if present, otherwise write
    //    a stub package so push_dir has a main package to anchor on.
    if capsule_wit.is_dir() {
        copy_dir_contents(&capsule_wit, &staging)?;
    } else {
        fs::write(staging.join("capsule.wit"), STUB_WIT_PACKAGE)
            .context("failed to write stub WIT package")?;
    }

    // 2. Add SDK shared contracts as a WIT dependency if available.
    if let Some(sdk_wit_path) = sdk_contracts {
        let deps_dir = staging.join("deps").join("astrid-contracts");
        fs::create_dir_all(&deps_dir)
            .with_context(|| format!("failed to create deps dir: {}", deps_dir.display()))?;
        fs::copy(&sdk_wit_path, deps_dir.join("astrid-contracts.wit")).with_context(|| {
            format!(
                "failed to copy shared SDK contracts from {}",
                sdk_wit_path.display()
            )
        })?;
        info!(
            "   Bundled shared SDK contracts from {}",
            sdk_wit_path.display()
        );
    }

    Ok(Some(staging))
}

/// Recursively copy directory contents from `src` into `dst`.
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in
        fs::read_dir(src).with_context(|| format!("failed to read directory: {}", src.display()))?
    {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // Use metadata() which follows symlinks, consistent with the archiver.
        let meta = entry.metadata()?;
        if meta.is_dir() {
            fs::create_dir_all(&to)
                .with_context(|| format!("failed to create dir: {}", to.display()))?;
            copy_dir_contents(&from, &to)?;
        } else if meta.is_file() {
            fs::copy(&from, &to)
                .with_context(|| format!("failed to copy {} → {}", from.display(), to.display()))?;
        }
    }
    Ok(())
}

/// Locate the `astrid-sdk` crate source directory and return the path to its
/// bundled `wit/astrid-contracts.wit`, or `None` if unavailable.
///
/// Searches the already-resolved cargo metadata for the `astrid-sdk` package
/// and reads the WIT file from the corresponding registry source directory.
fn find_sdk_contracts_wit(meta: &cargo_metadata::Metadata) -> Option<PathBuf> {
    let sdk_pkg = meta
        .packages
        .iter()
        .find(|p| p.name.as_str() == "astrid-sdk")?;

    // manifest_path is `<crate_src>/Cargo.toml`. Navigate to the crate root
    // and then to `wit/astrid-contracts.wit`.
    let crate_root = sdk_pkg.manifest_path.parent()?;
    let wit_path = crate_root
        .as_std_path()
        .join("wit")
        .join("astrid-contracts.wit");

    if wit_path.exists() {
        Some(wit_path)
    } else {
        warn!(
            "astrid-sdk does not bundle wit/astrid-contracts.wit at {}. \
             Shared contract types will not be available at install time.",
            wit_path.display()
        );
        None
    }
}

/// Extract capsule description from a compiled WASM binary.
///
/// Extract capsule description from the compiled WASM binary.
///
/// Previously called `astrid_export_schemas` via Extism. With the Component
/// Model migration, capsule metadata is extracted from `Capsule.toml` instead.
/// Returns `None` — description is set from the manifest.
fn extract_capsule_description(_wasm_path: &Path) -> Option<String> {
    // Component Model capsules don't export `astrid_export_schemas`.
    // Description comes from Capsule.toml [package] section instead.
    None
}

fn create_default_manifest(
    crate_name: &str,
    package_version: &str,
    wasm_name: &str,
) -> toml_edit::DocumentMut {
    let mut doc = toml_edit::DocumentMut::new();

    let mut package = toml_edit::Table::new();
    package.insert("name", toml_edit::value(crate_name));
    package.insert("version", toml_edit::value(package_version));
    package.insert("description", toml_edit::value(""));
    doc.insert("package", toml_edit::Item::Table(package));

    let mut comp = toml_edit::Table::new();
    comp.insert("id", toml_edit::value(crate_name));
    comp.insert("file", toml_edit::value(format!("{wasm_name}.wasm")));
    comp.insert("type", toml_edit::value("executable"));

    let mut comp_arr = toml_edit::ArrayOfTables::new();
    comp_arr.push(comp);
    doc.insert("component", toml_edit::Item::ArrayOfTables(comp_arr));

    doc
}

#[cfg(test)]
#[path = "rust_tests.rs"]
mod tests;
