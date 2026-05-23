//! Rust capsule builder — compiles a Rust crate to `wasm32-wasip2` and packages it.

use crate::archiver::pack_capsule_archive;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Stub WIT package written when a capsule has no local `wit/` directory.
/// Gives `push_dir` a main package to anchor on so deps can still be loaded.
const STUB_WIT_PACKAGE: &str = "package astrid:capsule-stub@1.0.0;\n\ninterface stub {}\n";

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
        &[],
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
fn compile_wasm(dir: &Path) -> Result<()> {
    info!("   Compiling capsule (release)...");
    let status = std::process::Command::new("cargo")
        .current_dir(dir)
        .args(["build", "--release"])
        .status()
        .context("Failed to spawn cargo build")?;

    if !status.success() {
        bail!(
            "Cargo build failed. Set `[build] target = \"wasm32-unknown-unknown\"` (Astrid-canonical) or `wasm32-wasip2` in `.cargo/config.toml` and install the matching `rustup target` component."
        );
    }
    Ok(())
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
