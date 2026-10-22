//! Admission and packaged-byte checks for prebuilt capsule components.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table};

/// The Rust builder emits one cdylib. Other components may only be prebuilt,
/// hash-pinned compute workers in `assets/`; their declarations are never
/// rewritten. The executable must be first because the runtime loads the
/// first manifest component.
pub(super) fn bind_manifest_to_packaged_wasm(
    doc: &mut DocumentMut,
    source: &Path,
    packaged_name: &str,
) -> Result<()> {
    super::validate_wasm_output_name(packaged_name.strip_suffix(".wasm").unwrap_or(packaged_name))?;
    if doc.get("component").is_none() {
        let mut component = Table::new();
        component.insert(
            "id",
            toml_edit::value(packaged_name.strip_suffix(".wasm").unwrap_or(packaged_name)),
        );
        component.insert("file", toml_edit::value(packaged_name));
        component.insert("type", toml_edit::value("executable"));
        let mut components = ArrayOfTables::new();
        components.push(component);
        doc.insert("component", Item::ArrayOfTables(components));
        return Ok(());
    }

    let components = doc["component"]
        .as_array_of_tables_mut()
        .context("Capsule.toml component must be an array of tables")?;
    let first = components
        .get_mut(0)
        .context("Capsule.toml must declare one executable cdylib")?;
    if !matches!(
        first.get("type").and_then(Item::as_str),
        None | Some("executable")
    ) {
        bail!("Capsule.toml first component must be the executable cdylib");
    }
    let has_file = first.get("file").is_some();
    let has_entrypoint = first.get("entrypoint").is_some();
    if has_file && has_entrypoint {
        bail!(
            "Capsule.toml component declares both `file` and `entrypoint`; refusing an ambiguous executable path"
        );
    }
    let key = if has_entrypoint { "entrypoint" } else { "file" };
    if first.get(key).is_some_and(|item| item.as_str().is_none()) {
        bail!("Capsule.toml component `{key}` must be a string");
    }
    first.insert(key, toml_edit::value(packaged_name));

    let pins = collect_pins(components, packaged_name)?;
    for (relative, expected) in &pins {
        let path = source.join(relative);
        reject_symlink_path(source, relative)?;
        let file = File::open(&path)
            .with_context(|| format!("pinned capsule asset is missing: {}", path.display()))?;
        if !file.metadata()?.is_file() {
            bail!(
                "pinned capsule asset must be a regular file: {}",
                path.display()
            );
        }
        verify_hash(file, expected, relative)?;
    }
    Ok(())
}

fn collect_pins(components: &ArrayOfTables, executable: &str) -> Result<BTreeMap<String, String>> {
    let mut ids = HashSet::new();
    let mut paths = HashSet::from([executable.to_owned()]);
    let mut pins = BTreeMap::new();
    for (index, component) in components.iter().enumerate() {
        if let Some(id) = component.get("id") {
            let id = id
                .as_str()
                .context("Capsule.toml component id must be a string")?;
            if id.is_empty() || !ids.insert(id.to_owned()) {
                bail!("Capsule.toml has an empty or duplicate component id");
            }
        } else if index != 0 {
            bail!("prebuilt compute-worker must have a component id");
        }
        if index != 0 {
            if component.get("type").and_then(Item::as_str) != Some("compute-worker") {
                bail!(
                    "additional components must be pinned compute-worker assets; this builder emits exactly one cdylib"
                );
            }
            let relative = component_path(component)?;
            insert_pin(component, relative, &mut paths, &mut pins)?;
        }
        if let Some(assets) = component.get("asset") {
            let assets = assets
                .as_array_of_tables()
                .context("component assets must be an array of tables")?;
            for asset in assets {
                let id = asset
                    .get("id")
                    .and_then(Item::as_str)
                    .context("component asset must have an id")?;
                if id.is_empty() || !ids.insert(id.to_owned()) {
                    bail!("Capsule.toml has an empty or duplicate component asset id");
                }
                let relative = asset
                    .get("file")
                    .and_then(Item::as_str)
                    .context("component asset must have a file path")?;
                insert_pin(asset, relative, &mut paths, &mut pins)?;
            }
        }
    }
    Ok(pins)
}

fn component_path(component: &Table) -> Result<&str> {
    match (component.get("file"), component.get("entrypoint")) {
        (Some(_), Some(_)) => bail!("component declares both `file` and `entrypoint`"),
        (Some(path), None) | (None, Some(path)) => path
            .as_str()
            .context("prebuilt compute-worker path must be a string"),
        (None, None) => bail!("prebuilt compute-worker needs a file path"),
    }
}

fn insert_pin(
    table: &Table,
    relative: &str,
    paths: &mut HashSet<String>,
    pins: &mut BTreeMap<String, String>,
) -> Result<()> {
    validate_asset_path(relative)?;
    if !paths.insert(relative.to_owned()) {
        bail!("Capsule.toml repeats packaged component or asset path: {relative}");
    }
    let hash = table
        .get("hash")
        .and_then(Item::as_str)
        .context("prebuilt component and asset paths require a blake3 hash")?;
    let digest = hash
        .strip_prefix("blake3:")
        .context("component asset hash must use blake3:<64 lowercase hex digits>")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("component asset hash must use blake3:<64 lowercase hex digits>");
    }
    pins.insert(relative.to_owned(), digest.to_owned());
    Ok(())
}

fn validate_asset_path(relative: &str) -> Result<()> {
    if relative.contains('\\') || relative.contains('\0') {
        bail!("unsafe component asset path: {relative}");
    }
    let path = Path::new(relative);
    let parts = path.components().collect::<Vec<_>>();
    if parts.len() < 2
        || parts[0] != Component::Normal("assets".as_ref())
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
        || parts
            .iter()
            .map(|part| part.as_os_str())
            .collect::<PathBuf>()
            != path
    {
        bail!("component asset must be a canonical relative path under assets/: {relative}");
    }
    Ok(())
}

fn reject_symlink_path(source: &Path, relative: &str) -> Result<()> {
    let mut path = source.to_path_buf();
    for component in Path::new(relative).components() {
        path.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("pinned capsule asset is missing: {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "pinned capsule asset cannot traverse a symlink: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn verify_hash(mut reader: impl Read, expected: &str, path: &str) -> Result<()> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hasher.finalize().to_hex().as_str() != expected {
        bail!("pinned capsule asset hash mismatch: {path}");
    }
    Ok(())
}

/// Recheck archived bytes after packaging so a source mutation between the
/// first hash and tar's read cannot produce a signed mismatch.
pub(super) fn verify_archive_pins(archive_path: &Path, manifest: &str) -> Result<()> {
    let doc = manifest.parse::<DocumentMut>()?;
    let components = doc["component"]
        .as_array_of_tables()
        .context("packaged manifest component array is missing")?;
    let executable = component_path(components.get(0).context("missing executable")?)?;
    let mut pins = collect_pins(components, executable)?;
    if pins.is_empty() {
        return Ok(());
    }
    let archive = File::open(archive_path)?;
    let mut tar = tar::Archive::new(GzDecoder::new(archive));
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(path) = path.to_str() else { continue };
        if let Some(expected) = pins.remove(path) {
            if !entry.header().entry_type().is_file() {
                bail!("pinned capsule asset is not a regular archive entry: {path}");
            }
            verify_hash(&mut entry, &expected, path)?;
        }
    }
    if let Some((path, _)) = pins.first_key_value() {
        bail!("pinned capsule asset is missing from archive: {path}");
    }
    Ok(())
}
