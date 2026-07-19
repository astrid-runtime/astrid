//! Rust capsule builder — compiles a Rust crate to `wasm32-wasip2` and packages it.

use crate::archiver::pack_capsule_archive;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tracing::{info, warn};

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

/// Cargo's argument separator for `CARGO_ENCODED_RUSTFLAGS` (ASCII unit
/// separator), used so individual flags may themselves contain spaces. A
/// `&str` (not `char`) so it can be passed straight to `join` / `split`
/// without allocating.
const RUSTFLAGS_SEP: &str = "\u{1f}";

/// Build a Rust capsule from a crate directory.
///
/// 1. `cargo build --target wasm32-wasip2 --release`
/// 2. Extract capsule description via Extism (`astrid_export_schemas`)
/// 3. Merge description into `Capsule.toml`
/// 4. Pack into `.capsule` archive
pub(crate) fn build(dir: &Path, output: Option<&str>) -> Result<()> {
    info!("Building Rust WASM capsule from {}", dir.display());

    verify_cargo_available()?;

    let (meta, crate_name, package_version, wasm_name) = resolve_package_metadata(dir)?;

    compile_wasm(dir)?;

    let wasm_path = locate_wasm_binary(dir, &meta, &wasm_name)?;
    let wasm_path = ensure_component(&wasm_path)?;

    let toml_content =
        build_manifest_content(dir, &wasm_path, &crate_name, &package_version, &wasm_name)?;
    let skill_files = declared_skill_files(dir, &toml_content)?;
    let skill_file_refs: Vec<&Path> = skill_files.iter().map(PathBuf::as_path).collect();

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
        &skill_file_refs,
        wit_staging.as_deref(),
    )?;

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
) -> Result<(cargo_metadata::Metadata, String, String, String)> {
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
    let wasm_name = crate_name.replace('-', "_");

    Ok((meta, crate_name, package_version, wasm_name))
}

/// Compile the capsule in release mode using whatever target the
/// capsule's own `.cargo/config.toml` selects.
///
/// The Astrid-canonical target is `wasm32-unknown-unknown` — zero
/// `wasi:*` imports, every host call audited through the
/// `astrid:*` SDK surface. Capsules may also target `wasm32-wasip2`
/// during the migration window (the kernel still satisfies wasi:*
/// for backwards compatibility), so this build step does NOT pass
/// `--target`; it lets the capsule decide.
///
/// When the capsule targets `wasm32-unknown-unknown` it additionally
/// injects the getrandom custom-backend cfg (see
/// [`encoded_rustflags_with_getrandom`]) so `astrid build` succeeds even
/// when a capsule's `.cargo/config.toml` is missing
/// `--cfg=getrandom_backend="custom"`. This is a safety net for the
/// canonical build tool, not a replacement: capsules still carry the flag
/// in config so a plain `cargo build` / `cargo test` (which never runs
/// through here) keeps linking `uuid` v4 / `HashMap`.
fn compile_wasm(dir: &Path) -> Result<()> {
    info!("   Compiling capsule (release)...");

    let (config_target, config_flags) = cargo_config_target_and_rustflags(dir);
    // `CARGO_BUILD_TARGET` (if the caller set it) overrides the config-file
    // target, mirroring Cargo's own precedence.
    let env_target = std::env::var("CARGO_BUILD_TARGET").ok();
    let target = env_target.as_deref().or(config_target.as_deref());

    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(dir).args(["build", "--release"]);

    if let Some(encoded) = encoded_rustflags_with_getrandom(
        target,
        &config_flags,
        std::env::var("CARGO_ENCODED_RUSTFLAGS").ok().as_deref(),
        std::env::var("RUSTFLAGS").ok().as_deref(),
    ) {
        // Capsule targets `wasm32-unknown-unknown`, so guarantee the getrandom
        // custom-backend cfg is present. Because host != wasm this is a
        // cross-compile, so the flag reaches only the wasm artifacts — host
        // build scripts / proc-macros are untouched. We set
        // `CARGO_ENCODED_RUSTFLAGS` (and drop `RUSTFLAGS`, whose value we have
        // already folded in) so the two sources can't both apply and so flags
        // containing spaces survive.
        cmd.env("CARGO_ENCODED_RUSTFLAGS", encoded);
        cmd.env_remove("RUSTFLAGS");
    }

    let status = cmd.status().context("Failed to spawn cargo build")?;

    if !status.success() {
        bail!(
            "Cargo build failed. Set `[build] target = \"wasm32-unknown-unknown\"` (Astrid-canonical) or `wasm32-wasip2` in `.cargo/config.toml` and install the matching `rustup target` component."
        );
    }
    Ok(())
}

/// Read the build target and any author-declared `rustflags` from a capsule's
/// local `.cargo/config.toml` (or the legacy `.cargo/config`).
///
/// Returns `(target, rustflags)`. `target` is the `[build] target` string if
/// set. `rustflags` is the effective list Cargo would apply to the wasm
/// target: `[target."wasm32-unknown-unknown"].rustflags` if present, otherwise
/// `[build].rustflags`, otherwise empty. Cargo honours only one of those two
/// sources (target-scoped wins), so we mirror that precedence rather than
/// concatenating them. A `[build] target` written as an array (multi-target
/// build) is intentionally ignored — we only auto-inject for a single, plain
/// `wasm32-unknown-unknown` target.
fn cargo_config_target_and_rustflags(dir: &Path) -> (Option<String>, Vec<String>) {
    let Some(doc) = [".cargo/config.toml", ".cargo/config"]
        .iter()
        .map(|name| dir.join(name))
        .find_map(|p| fs::read_to_string(p).ok())
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
    else {
        return (None, Vec::new());
    };

    let target = doc
        .get("build")
        .and_then(|b| b.get("target"))
        .and_then(toml_edit::Item::as_str)
        .map(str::to_owned);

    // Cargo accepts `rustflags` as either an array of strings or a single
    // space-separated string; handle both so a string-form value isn't
    // silently dropped (which would let our env injection clobber it).
    let read_flags = |item: Option<&toml_edit::Item>| -> Option<Vec<String>> {
        item.and_then(|it| {
            if let Some(arr) = it.as_array() {
                Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect(),
                )
            } else {
                it.as_str()
                    .map(|s| s.split_whitespace().map(str::to_owned).collect())
            }
        })
    };

    let target_scoped = doc
        .get("target")
        .and_then(|t| t.get(GETRANDOM_TARGET))
        .and_then(|t| t.get("rustflags"));
    let build_scoped = doc.get("build").and_then(|b| b.get("rustflags"));

    let rustflags = read_flags(target_scoped)
        .or_else(|| read_flags(build_scoped))
        .unwrap_or_default();

    (target, rustflags)
}

/// Compute the `CARGO_ENCODED_RUSTFLAGS` value for a capsule build, injecting
/// the getrandom custom-backend cfg when — and only when — the capsule targets
/// `wasm32-unknown-unknown`. Returns `None` (leave the environment untouched)
/// for any other target.
///
/// Flags are concatenated in order — inherited environment flags
/// (`CARGO_ENCODED_RUSTFLAGS` takes precedence over `RUSTFLAGS`), then the
/// capsule's own config `rustflags`, then the getrandom cfg. We deliberately
/// *merge* rather than let the env override config (which is Cargo's real
/// precedence): a build tool silently dropping a flag the author or developer
/// set would be a nasty surprise. The only flags it can't see are ones set in
/// a *parent* config (above the capsule dir); capsules keep their `rustflags`
/// in their own `.cargo/config.toml`, so that's a non-issue in practice.
///
/// Only the getrandom cfg is de-duplicated. Inherited and config flags are
/// kept verbatim: de-duping individual tokens would corrupt multi-token flags
/// like `-C opt-level=3` followed by `-C debuginfo=2` (the second `-C` would
/// be dropped, yielding invalid `rustc` input). Duplicate whole flags are
/// harmless to `rustc`.
fn encoded_rustflags_with_getrandom(
    target: Option<&str>,
    config_flags: &[String],
    inherited_encoded: Option<&str>,
    inherited_plain: Option<&str>,
) -> Option<String> {
    if target != Some(GETRANDOM_TARGET) {
        return None;
    }

    let mut flags: Vec<String> = if let Some(enc) = inherited_encoded {
        enc.split(RUSTFLAGS_SEP)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    } else if let Some(plain) = inherited_plain {
        plain.split_whitespace().map(str::to_owned).collect()
    } else {
        Vec::new()
    };

    flags.extend(config_flags.iter().cloned());

    if !flags.iter().any(|f| f == GETRANDOM_CUSTOM_CFG) {
        flags.push(GETRANDOM_CUSTOM_CFG.to_owned());
    }

    Some(flags.join(RUSTFLAGS_SEP))
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
    let component = wit_component::ComponentEncoder::default()
        .validate(true)
        .module(&bytes)
        .context("ComponentEncoder rejected the core wasm — wit-bindgen `generate!` may be missing or producing the wrong section")?
        .encode()
        .context("ComponentEncoder failed to emit a component")?;
    // Overwrite the original artifact path so the capsule's
    // `Capsule.toml [[component]] file = "<crate>.wasm"` directive
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

/// Locate the compiled WASM binary in the target directory. We don't
/// know which target was used (the capsule's `.cargo/config.toml`
/// decides), so probe the known guest targets in canonical-first order
/// and accept the first one that exists. The capsule build wrapping
/// step below treats `wasm32-unknown-unknown` outputs as core wasm
/// modules that need to be wrapped into a component; `wasm32-wasip2`
/// outputs are already components.
fn locate_wasm_binary(
    dir: &Path,
    meta: &cargo_metadata::Metadata,
    wasm_name: &str,
) -> Result<PathBuf> {
    const TARGETS: &[&str] = &["wasm32-unknown-unknown", "wasm32-wasip2"];
    let local_target = dir.join("target");
    let workspace_target = meta
        .workspace_root
        .clone()
        .into_std_path_buf()
        .join("target");
    for target in TARGETS {
        for root in &[&local_target, &workspace_target] {
            let candidate = root
                .join(target)
                .join("release")
                .join(format!("{wasm_name}.wasm"));
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "Could not locate compiled WASM binary under `target/{{wasm32-unknown-unknown,wasm32-wasip2}}/release/{wasm_name}.wasm` in {} or workspace root",
        dir.display()
    );
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

    let base_toml_path = dir.join("Capsule.toml");
    let mut toml_doc = if base_toml_path.exists() {
        let content = fs::read_to_string(&base_toml_path).context("Failed to read Capsule.toml")?;
        content
            .parse::<toml_edit::DocumentMut>()
            .context("Failed to parse Capsule.toml")?
    } else {
        create_default_manifest(crate_name, package_version, wasm_name)
    };

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

/// Resolve the files referenced by `[[skill]]` declarations for archiving.
///
/// Declared assets are untrusted manifest input. They must remain at a
/// relative, traversal-free path inside the capsule source tree, and must
/// resolve to regular files. The source-tree path formed from the declared
/// relative path is returned (rather than its canonical target) so the archive
/// layout exactly matches `SkillDef::file` even when an in-tree symlink is
/// dereferenced.
fn declared_skill_files(dir: &Path, manifest_content: &str) -> Result<Vec<PathBuf>> {
    let doc = manifest_content
        .parse::<toml_edit::DocumentMut>()
        .context("Failed to parse synthesized Capsule.toml for declared skills")?;
    let Some(skills) = doc
        .get("skill")
        .and_then(toml_edit::Item::as_array_of_tables)
    else {
        return Ok(Vec::new());
    };

    let canonical_dir = dir.canonicalize().with_context(|| {
        format!(
            "Failed to resolve capsule source directory {}",
            dir.display()
        )
    })?;
    let mut files = BTreeMap::new();

    for skill in skills {
        let name = skill
            .get("name")
            .and_then(toml_edit::Item::as_str)
            .unwrap_or("<unnamed>");
        let declared = skill
            .get("file")
            .and_then(toml_edit::Item::as_str)
            .with_context(|| format!("skill {name:?} is missing a string `file` path"))?;
        let relative = Path::new(declared);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || declared.contains('\\')
            || declared.contains("://")
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("skill {name:?} has an unsafe file path: {declared:?}");
        }

        let source = dir.join(relative);
        let canonical_source = source.canonicalize().with_context(|| {
            format!(
                "skill {name:?} file does not exist or cannot be resolved: {}",
                source.display()
            )
        })?;
        if !canonical_source.starts_with(&canonical_dir) || !canonical_source.is_file() {
            bail!(
                "skill {name:?} file must resolve to a regular file inside the capsule source: {}",
                source.display()
            );
        }

        files.entry(relative.to_path_buf()).or_insert(source);
    }

    Ok(files.into_values().collect())
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
mod tests {
    use super::*;

    fn manifest_with_skill(file: &str) -> String {
        format!(
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[[skill]]\nname = \"test-skill\"\nfile = {file:?}\n"
        )
    }

    fn decode(encoded: &str) -> Vec<String> {
        encoded.split(RUSTFLAGS_SEP).map(str::to_owned).collect()
    }

    #[test]
    fn no_injection_for_non_wasm_target() {
        assert_eq!(
            encoded_rustflags_with_getrandom(Some("wasm32-wasip2"), &[], None, None),
            None
        );
        assert_eq!(
            encoded_rustflags_with_getrandom(None, &[], None, None),
            None
        );
    }

    #[test]
    fn injects_cfg_when_capsule_declares_nothing() {
        let encoded =
            encoded_rustflags_with_getrandom(Some(GETRANDOM_TARGET), &[], None, None).unwrap();
        assert_eq!(decode(&encoded), vec![GETRANDOM_CUSTOM_CFG.to_owned()]);
    }

    #[test]
    fn does_not_duplicate_an_already_present_cfg() {
        // The current per-capsule `.cargo/config.toml` case: the flag is
        // already there, so injection must be a no-op (no double flag).
        let config = vec![GETRANDOM_CUSTOM_CFG.to_owned()];
        let encoded =
            encoded_rustflags_with_getrandom(Some(GETRANDOM_TARGET), &config, None, None).unwrap();
        assert_eq!(decode(&encoded), vec![GETRANDOM_CUSTOM_CFG.to_owned()]);
    }

    #[test]
    fn preserves_other_config_rustflags() {
        let config = vec!["-C".to_owned(), "target-feature=+simd128".to_owned()];
        let encoded =
            encoded_rustflags_with_getrandom(Some(GETRANDOM_TARGET), &config, None, None).unwrap();
        assert_eq!(
            decode(&encoded),
            vec![
                "-C".to_owned(),
                "target-feature=+simd128".to_owned(),
                GETRANDOM_CUSTOM_CFG.to_owned(),
            ]
        );
    }

    #[test]
    fn preserves_repeated_flag_tokens() {
        // Regression: de-duping individual tokens must NOT drop a repeated
        // `-C`, which would fuse two separate flags into invalid rustc input
        // (`-C opt-level=3` + `-C debuginfo=2` -> `-C opt-level=3 debuginfo=2`).
        let config = vec![
            "-C".to_owned(),
            "opt-level=3".to_owned(),
            "-C".to_owned(),
            "debuginfo=2".to_owned(),
        ];
        let encoded =
            encoded_rustflags_with_getrandom(Some(GETRANDOM_TARGET), &config, None, None).unwrap();
        assert_eq!(
            decode(&encoded),
            vec![
                "-C".to_owned(),
                "opt-level=3".to_owned(),
                "-C".to_owned(),
                "debuginfo=2".to_owned(),
                GETRANDOM_CUSTOM_CFG.to_owned(),
            ]
        );
    }

    #[test]
    fn merges_inherited_plain_rustflags() {
        let encoded = encoded_rustflags_with_getrandom(
            Some(GETRANDOM_TARGET),
            &[],
            None,
            Some("--cfg=foo -Cdebuginfo=2"),
        )
        .unwrap();
        assert_eq!(
            decode(&encoded),
            vec![
                "--cfg=foo".to_owned(),
                "-Cdebuginfo=2".to_owned(),
                GETRANDOM_CUSTOM_CFG.to_owned(),
            ]
        );
    }

    #[test]
    fn encoded_env_takes_precedence_over_plain() {
        // When both are set Cargo reads the encoded form; we must too.
        let encoded = encoded_rustflags_with_getrandom(
            Some(GETRANDOM_TARGET),
            &[],
            Some("--cfg=from_encoded"),
            Some("--cfg=from_plain"),
        )
        .unwrap();
        assert_eq!(
            decode(&encoded),
            vec![
                "--cfg=from_encoded".to_owned(),
                GETRANDOM_CUSTOM_CFG.to_owned(),
            ]
        );
    }

    #[test]
    fn reads_target_and_rustflags_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "[build]\n\
             target = \"wasm32-unknown-unknown\"\n\n\
             [target.wasm32-unknown-unknown]\n\
             rustflags = [\"--cfg=getrandom_backend=\\\"custom\\\"\"]\n",
        )
        .unwrap();

        let (target, flags) = cargo_config_target_and_rustflags(dir.path());
        assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
        assert_eq!(flags, vec![GETRANDOM_CUSTOM_CFG.to_owned()]);
    }

    #[test]
    fn reads_string_form_rustflags_from_config() {
        // Cargo allows `rustflags` as a single space-separated string, not
        // just an array — parse both forms.
        let dir = tempfile::tempdir().unwrap();
        let cargo_dir = dir.path().join(".cargo");
        fs::create_dir_all(&cargo_dir).unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "[build]\n\
             target = \"wasm32-unknown-unknown\"\n\
             rustflags = \"-C opt-level=3\"\n",
        )
        .unwrap();

        let (target, flags) = cargo_config_target_and_rustflags(dir.path());
        assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
        assert_eq!(flags, vec!["-C".to_owned(), "opt-level=3".to_owned()]);
    }

    #[test]
    fn missing_config_yields_no_target_or_flags() {
        let dir = tempfile::tempdir().unwrap();
        let (target, flags) = cargo_config_target_and_rustflags(dir.path());
        assert_eq!(target, None);
        assert!(flags.is_empty());
    }

    #[test]
    fn resolves_declared_skill_files_at_their_archive_paths() {
        let dir = tempfile::tempdir().unwrap();
        let skill = dir.path().join("skills/test/SKILL.md");
        fs::create_dir_all(skill.parent().unwrap()).unwrap();
        fs::write(&skill, "# Test skill").unwrap();

        let manifest = manifest_with_skill("skills/test/SKILL.md");
        let files = declared_skill_files(dir.path(), &manifest).unwrap();

        assert_eq!(files, vec![skill]);

        let archive_path = dir.path().join("test.capsule");
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        pack_capsule_archive(&archive_path, &manifest, None, dir.path(), &refs, None).unwrap();
        let decoder = flate2::read::GzDecoder::new(fs::File::open(archive_path).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect();
        assert!(entries.contains(&PathBuf::from("skills/test/SKILL.md")));
    }

    #[test]
    fn rejects_missing_or_escaping_declared_skill_files() {
        let dir = tempfile::tempdir().unwrap();

        let missing =
            declared_skill_files(dir.path(), &manifest_with_skill("skills/missing/SKILL.md"))
                .unwrap_err();
        assert!(missing.to_string().contains("does not exist"));

        let traversal =
            declared_skill_files(dir.path(), &manifest_with_skill("../SKILL.md")).unwrap_err();
        assert!(traversal.to_string().contains("unsafe file path"));

        let absolute =
            declared_skill_files(dir.path(), &manifest_with_skill("/tmp/SKILL.md")).unwrap_err();
        assert!(absolute.to_string().contains("unsafe file path"));

        let backslashes =
            declared_skill_files(dir.path(), &manifest_with_skill("skills\\test\\SKILL.md"))
                .unwrap_err();
        assert!(backslashes.to_string().contains("unsafe file path"));

        let scheme = declared_skill_files(
            dir.path(),
            &manifest_with_skill("home://skills/test/SKILL.md"),
        )
        .unwrap_err();
        assert!(scheme.to_string().contains("unsafe file path"));
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn rejects_declared_skill_symlinks_that_escape_the_source_tree() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_skill = outside.path().join("SKILL.md");
        fs::write(&outside_skill, "# Outside").unwrap();
        let skill = dir.path().join("skills/test/SKILL.md");
        fs::create_dir_all(skill.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_skill, &skill).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&outside_skill, &skill).unwrap();

        let error = declared_skill_files(dir.path(), &manifest_with_skill("skills/test/SKILL.md"))
            .unwrap_err();
        assert!(error.to_string().contains("inside the capsule source"));
    }
}
