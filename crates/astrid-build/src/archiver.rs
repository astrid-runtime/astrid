use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek};
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

    // Gzip's default header records the current wall-clock time. Pinning it is
    // required for byte-for-byte reproducible archives from identical inputs.
    let enc = GzBuilder::new()
        .mtime(0)
        .write(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);
    // Every entry is written through an explicit canonical header below.
    // HeaderMode alone does not normalize source permission bits.
    tar.mode(tar::HeaderMode::Deterministic);

    // Explicitly enforce symlink dereferencing (this is already the default in the tar
    // crate, but we state it explicitly because the install path rejects symlinks as a
    // security measure and we want this invariant to survive upstream default changes).
    tar.follow_symlinks(true);

    // 1. Write the synthesized Capsule.toml directly from memory
    let mut header = deterministic_header(
        manifest_content.len() as u64,
        0o644,
        tar::EntryType::Regular,
    );
    tar.append_data(&mut header, "Capsule.toml", manifest_content.as_bytes())
        .context("Failed to write Capsule.toml to archive")?;

    // 2. Append the WASM binary (if present)
    if let Some(wasm) = wasm_path {
        if wasm.exists() {
            let file_name = wasm.file_name().unwrap_or_default();
            append_file(&mut tar, Path::new(file_name), wasm)?;
        } else {
            anyhow::bail!("WASM binary not found at {}", wasm.display());
        }
    }

    // 3. Append additional contextual and opaque asset files.
    // Use a cycle-safe recursive walk instead of tar's append_dir_all, because
    // follow_symlinks(true) + append_dir_all has no cycle detection — a symlink
    // pointing to an ancestor directory would cause infinite recursion and OOM.
    let mut ordered_files: Vec<(&Path, PathBuf)> = additional_files
        .iter()
        .filter(|path| path.exists())
        .map(|path| {
            let relative = path
                .strip_prefix(base_dir)
                .unwrap_or(Path::new(path.file_name().unwrap_or_default()))
                .to_path_buf();
            (*path, relative)
        })
        .collect();
    ordered_files.sort_unstable_by(|left, right| left.1.cmp(&right.1));

    let mut visited = HashSet::new();
    for (file_path, rel_path) in ordered_files {
        if file_path.exists() {
            if file_path.is_dir() {
                append_dir_recursive(&mut tar, &rel_path, file_path, &mut visited)?;
            } else {
                append_file(&mut tar, &rel_path, file_path)?;
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

    let enc = tar
        .into_inner()
        .context("Failed to finalize capsule tar stream")?;
    enc.finish()
        .context("Failed to finalize capsule gzip stream")?;

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

    // Directory contents and execute intent are the only permission semantics
    // carried into the package. Checkout ownership and incidental mode bits do
    // not perturb the archive.
    let mut header = deterministic_header(0, 0o755, tar::EntryType::Directory);
    tar.append_data(&mut header, archive_path, std::io::empty())
        .with_context(|| {
            format!(
                "Failed to append directory to archive: {}",
                fs_path.display()
            )
        })?;

    // Filesystem iteration order is unspecified. Sort before recursion so the
    // tar stream is stable across filesystems and repeated builds.
    let mut entries = fs::read_dir(fs_path)
        .with_context(|| format!("Failed to read directory: {}", fs_path.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_unstable_by_key(fs::DirEntry::file_name);

    // Recurse into children
    for entry in entries {
        let child_fs = entry.path();
        let child_archive = archive_path.join(entry.file_name());

        // Use fs::metadata (follows symlinks) to get the resolved type
        let metadata = fs::metadata(&child_fs)
            .with_context(|| format!("Failed to read metadata for {}", child_fs.display()))?;

        if metadata.is_dir() {
            append_dir_recursive(tar, &child_archive, &child_fs, visited)?;
        } else {
            append_file(tar, &child_archive, &child_fs)?;
        }
    }

    Ok(())
}

fn append_file(
    tar: &mut tar::Builder<GzEncoder<File>>,
    archive_path: &Path,
    fs_path: &Path,
) -> Result<()> {
    let mut file = File::open(fs_path)
        .with_context(|| format!("Failed to open file for packing: {}", fs_path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect file for packing: {}", fs_path.display()))?;
    let mode = normalized_file_mode(&metadata, &mut file)?;
    let mut header = deterministic_header(metadata.len(), mode, tar::EntryType::Regular);
    tar.append_data(&mut header, archive_path, &mut file)
        .with_context(|| format!("Failed to append file to archive: {}", fs_path.display()))
}

fn normalized_file_mode(metadata: &fs::Metadata, file: &mut File) -> Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 != 0 {
            return Ok(0o755);
        }
    }

    // Windows has no Unix execute bits. Preserve executable intent from
    // self-describing file formats so a checked-out script or native binary
    // does not become data merely because the build host lacks that metadata.
    let mut prefix = [0_u8; 4];
    let read = file
        .read(&mut prefix)
        .context("Failed to inspect executable intent")?;
    file.rewind()
        .context("Failed to rewind file after executable-intent inspection")?;
    Ok(if executable_magic(&prefix[..read]) {
        0o755
    } else {
        0o644
    })
}

fn executable_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(b"#!")
        || prefix.starts_with(b"\x7fELF")
        || prefix.starts_with(b"MZ")
        || matches!(
            prefix,
            [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
                | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
        )
}

fn deterministic_header(size: u64, mode: u32, entry_type: tar::EntryType) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(tar::DETERMINISTIC_TIMESTAMP);
    header.set_entry_type(entry_type);
    header.set_cksum();
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_crypto::KeyPair;

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

    #[test]
    fn signed_archives_are_reproducible_across_input_order_and_mtime() {
        let source = tempfile::tempdir().unwrap();
        let first = source.path().join("z-last.txt");
        let assets_dir = source.path().join("assets");
        let nested = assets_dir.join("nested/first.txt");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&first, "same first bytes").unwrap();
        fs::write(&nested, "same nested bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o640)).unwrap();
        }

        let manifest = "[package]\nname = \"reproducible\"\nversion = \"1.0.0\"\n";
        let archive_a = source.path().join("a.capsule");
        let archive_b = source.path().join("b.capsule");
        let key = KeyPair::generate();

        // Deliberately provide reverse lexical order for the first build.
        pack_capsule_archive(
            &archive_a,
            manifest,
            None,
            source.path(),
            &[first.as_path(), assets_dir.as_path()],
            None,
        )
        .unwrap();
        crate::artifact::sign_archive(&archive_a, &key).unwrap();

        // Move source mtimes while retaining the exact bytes, then reverse the
        // caller-provided input order. This would perturb the old archive
        // headers without adding a timing-dependent sleep to the test.
        let changed_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567);
        fs::OpenOptions::new()
            .write(true)
            .open(&first)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(changed_time))
            .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&nested)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(changed_time))
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&first, fs::Permissions::from_mode(0o644)).unwrap();
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o664)).unwrap();
        }
        pack_capsule_archive(
            &archive_b,
            manifest,
            None,
            source.path(),
            &[assets_dir.as_path(), first.as_path()],
            None,
        )
        .unwrap();
        crate::artifact::sign_archive(&archive_b, &key).unwrap();

        assert_eq!(fs::read(archive_a).unwrap(), fs::read(archive_b).unwrap());
    }

    #[test]
    fn signed_archive_bytes_include_the_signing_identity() {
        let source = tempfile::tempdir().unwrap();
        let payload = source.path().join("payload.txt");
        fs::write(&payload, "same payload").unwrap();
        let archive_a = source.path().join("key-a.capsule");
        let archive_b = source.path().join("key-b.capsule");
        let manifest = "[package]\nname = \"signer-input\"\nversion = \"1.0.0\"\n";

        for archive in [&archive_a, &archive_b] {
            pack_capsule_archive(
                archive,
                manifest,
                None,
                source.path(),
                &[payload.as_path()],
                None,
            )
            .unwrap();
        }
        crate::artifact::sign_archive(&archive_a, &KeyPair::generate()).unwrap();
        crate::artifact::sign_archive(&archive_b, &KeyPair::generate()).unwrap();

        assert_ne!(fs::read(archive_a).unwrap(), fs::read(archive_b).unwrap());
    }

    #[test]
    fn synthesized_and_filesystem_headers_are_normalized() {
        let source = tempfile::tempdir().unwrap();
        let payload = source.path().join("payload.txt");
        let executable = source.path().join("run.sh");
        let assets = source.path().join("assets");
        fs::write(&payload, "payload").unwrap();
        fs::write(&executable, "#!/bin/sh\n").unwrap();
        fs::create_dir(&assets).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&assets, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let archive_path = source.path().join("headers.capsule");

        pack_capsule_archive(
            &archive_path,
            "[package]\nname = \"headers\"\nversion = \"1.0.0\"\n",
            None,
            source.path(),
            &[payload.as_path(), executable.as_path(), assets.as_path()],
            None,
        )
        .unwrap();

        let file = File::open(archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        assert_eq!(decoder.header().unwrap().mtime(), 0);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let header = entry.header();
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
            assert_eq!(header.mtime().unwrap(), tar::DETERMINISTIC_TIMESTAMP);
            let path = entry.path().unwrap();
            let expected_mode = if path == Path::new("assets") || path == Path::new("run.sh") {
                0o755
            } else {
                0o644
            };
            assert_eq!(header.mode().unwrap(), expected_mode);
        }
    }
}
