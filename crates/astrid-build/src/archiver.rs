use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const LARGE_ARCHIVE_BYTES: u64 = 50 * 1024 * 1024; // 50 MB
const OPAQUE_ASSET_DIRS: &[&str] = &["assets", "skills"];

/// Find files under conventional opaque asset directories without assigning
/// them manifest or runtime semantics.
///
/// `assets/` is the generic surface. `skills/` remains packable as opaque data
/// so existing capsule sources do not lose files when the old `[[skill]]`
/// protocol is removed. Symlinks are rejected so recursive discovery cannot
/// escape the capsule source tree.
pub(crate) fn discover_opaque_assets(base_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for name in OPAQUE_ASSET_DIRS {
        let root = base_dir.join(name);
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to inspect asset path: {}", root.display()));
            },
        };
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "opaque capsule asset directories cannot be symlinks: {}",
                root.display()
            );
        }
        if !metadata.is_dir() {
            anyhow::bail!("opaque asset path must be a directory: {}", root.display());
        }
        let mut pending = vec![root];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)
                .with_context(|| format!("Failed to read asset directory: {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    anyhow::bail!(
                        "opaque capsule assets cannot be symlinks: {}",
                        path.display()
                    );
                }
                if file_type.is_dir() {
                    pending.push(path);
                } else if file_type.is_file() {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Packages a set of files and directories into a single `.capsule` (tar.gz) archive.
pub(crate) fn pack_capsule_archive(
    output_path: &Path,
    manifest_content: &str,
    wasm_path: Option<&Path>,
    base_dir: &Path,
    additional_files: &[&Path],
    wit_dir: Option<&Path>,
) -> Result<()> {
    info!("📦 Packing capsule archive into {}", output_path.display());

    let tar_gz = File::create(output_path)
        .with_context(|| format!("Failed to create archive file: {}", output_path.display()))?;

    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    // Explicitly enforce symlink dereferencing (this is already the default in the tar
    // crate, but we state it explicitly because the install path rejects symlinks as a
    // security measure and we want this invariant to survive upstream default changes).
    tar.follow_symlinks(true);

    // 1. Write the synthesized Capsule.toml directly from memory
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "Capsule.toml", manifest_content.as_bytes())
        .context("Failed to write Capsule.toml to archive")?;

    // 2. Append the WASM binary (if present)
    if let Some(wasm) = wasm_path {
        if wasm.exists() {
            let mut wasm_file = File::open(wasm).with_context(|| {
                format!("Failed to open WASM binary for packing: {}", wasm.display())
            })?;
            let file_name = wasm.file_name().unwrap_or_default();
            tar.append_file(file_name, &mut wasm_file)
                .with_context(|| {
                    format!(
                        "Failed to append WASM binary to archive: {}",
                        wasm.display()
                    )
                })?;
        } else {
            anyhow::bail!("WASM binary not found at {}", wasm.display());
        }
    }

    // 3. Append additional contextual and opaque asset files.
    // Use a cycle-safe recursive walk instead of tar's append_dir_all, because
    // follow_symlinks(true) + append_dir_all has no cycle detection — a symlink
    // pointing to an ancestor directory would cause infinite recursion and OOM.
    let mut visited = HashSet::new();
    for file_path in additional_files {
        if file_path.exists() {
            let rel_path = file_path
                .strip_prefix(base_dir)
                .unwrap_or(Path::new(file_path.file_name().unwrap_or_default()));

            if file_path.is_dir() {
                append_dir_recursive(&mut tar, rel_path, file_path, &mut visited)?;
            } else {
                let mut f = File::open(file_path).with_context(|| {
                    format!("Failed to open file for packing: {}", file_path.display())
                })?;
                tar.append_file(rel_path, &mut f).with_context(|| {
                    format!("Failed to append file to archive: {}", file_path.display())
                })?;
            }
        }
    }

    // 4. If a staged wit/ directory was provided, recursively add its contents
    //    under the archive path `wit/`. This bundles both the capsule's own
    //    WIT files and any shared dependencies (e.g. astrid-sdk contracts)
    //    that are needed for install-time schema resolution.
    if let Some(wit) = wit_dir
        && wit.is_dir()
    {
        let mut wit_visited = HashSet::new();
        append_dir_recursive(&mut tar, Path::new("wit"), wit, &mut wit_visited)?;
    }

    tar.finish().context("Failed to finalize capsule archive")?;

    // Warn if archive is large (node_modules can bloat Tier 2 capsules)
    if let Ok(meta) = fs::metadata(output_path) {
        let size_bytes = meta.len();
        if size_bytes > LARGE_ARCHIVE_BYTES {
            // Precision loss is irrelevant for a human-readable MB display value
            #[expect(clippy::cast_precision_loss)]
            let size_mb = size_bytes as f64 / (1024.0 * 1024.0);
            warn!("⚠️  Capsule archive is {size_mb:.1} MB — consider trimming dependencies");
        }
    }

    info!("✅ Capsule packaged successfully!");
    Ok(())
}

/// Recursively append a directory to the tar archive with symlink cycle detection.
///
/// Tracks visited directories by canonical path. If a symlink resolves to a
/// directory we've already visited (cycle), it is skipped with a warning instead
/// of causing infinite recursion.
fn append_dir_recursive(
    tar: &mut tar::Builder<GzEncoder<File>>,
    archive_path: &Path,
    fs_path: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    // Canonicalize resolves symlinks to their real path, so a symlink pointing
    // to an ancestor will resolve to the same canonical path we already visited.
    let canonical = fs::canonicalize(fs_path).with_context(|| {
        format!(
            "Failed to resolve path for cycle detection: {}",
            fs_path.display()
        )
    })?;

    if !visited.insert(canonical) {
        warn!(
            "Skipping symlink cycle at {} — target was already archived",
            fs_path.display()
        );
        return Ok(());
    }

    // Append the directory entry itself
    tar.append_dir(archive_path, fs_path).with_context(|| {
        format!(
            "Failed to append directory to archive: {}",
            fs_path.display()
        )
    })?;

    // Recurse into children
    for entry in fs::read_dir(fs_path)
        .with_context(|| format!("Failed to read directory: {}", fs_path.display()))?
    {
        let entry = entry?;
        let child_fs = entry.path();
        let child_archive = archive_path.join(entry.file_name());

        // Use fs::metadata (follows symlinks) to get the resolved type
        let metadata = fs::metadata(&child_fs)
            .with_context(|| format!("Failed to read metadata for {}", child_fs.display()))?;

        if metadata.is_dir() {
            append_dir_recursive(tar, &child_archive, &child_fs, visited)?;
        } else {
            let mut f = File::open(&child_fs).with_context(|| {
                format!("Failed to open file for packing: {}", child_fs.display())
            })?;
            tar.append_file(&child_archive, &mut f).with_context(|| {
                format!("Failed to append file to archive: {}", child_fs.display())
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_assets_are_packaged_without_manifest_metadata() {
        let source = tempfile::tempdir().unwrap();
        let assets = source.path().join("assets/reference.txt");
        let skill = source.path().join("skills/example/SKILL.md");
        fs::create_dir_all(assets.parent().unwrap()).unwrap();
        fs::create_dir_all(skill.parent().unwrap()).unwrap();
        fs::write(&assets, "reference").unwrap();
        fs::write(&skill, "# Example").unwrap();

        let files = discover_opaque_assets(source.path()).unwrap();
        assert_eq!(files, vec![assets, skill]);

        let archive_path = source.path().join("example.capsule");
        let manifest = "[package]\nname = \"example\"\nversion = \"1.0.0\"\n";
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        pack_capsule_archive(&archive_path, manifest, None, source.path(), &refs, None).unwrap();

        let decoder = flate2::read::GzDecoder::new(File::open(archive_path).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let entries: Vec<PathBuf> = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect();
        assert!(entries.contains(&PathBuf::from("assets/reference.txt")));
        assert!(entries.contains(&PathBuf::from("skills/example/SKILL.md")));
        assert!(!manifest.contains("[[skill]]"));
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn opaque_asset_symlinks_are_rejected() {
        let source = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let assets = source.path().join("assets");
        fs::create_dir(&assets).unwrap();
        let link = assets.join("outside");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), &link).unwrap();

        let error = discover_opaque_assets(source.path()).unwrap_err();
        assert!(error.to_string().contains("cannot be symlinks"));
    }
}
