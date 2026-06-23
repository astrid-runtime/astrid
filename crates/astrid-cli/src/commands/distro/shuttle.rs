//! `.shuttle` archive format — a signed, offline-installable distro bundle.
//!
//! A `.shuttle` is a deterministic gzipped tar laid out as:
//!
//! ```text
//! Distro.toml            # the manifest, verbatim bytes
//! Distro.lock            # resolved lock with per-capsule blake3 + manifest_hash
//! Distro.sig             # hex ed25519 signature over blake3(canonical_json(lock))
//! capsules/<name>.capsule  # one packed capsule per selected entry
//! ```
//!
//! ## Why a custom packer instead of reusing `unpack_and_install`
//!
//! [`astrid_capsule_install::archive::unpack_and_install`] is for a
//! single `.capsule` and *installs* as a side effect. A `.shuttle`
//! holds many capsules plus signing material and must be unpacked to a
//! local mirror *without* installing — verification happens between
//! unpack and install. The hardened path-traversal / symlink defense is
//! reproduced here (it is small and security-critical, and duplicating
//! it keeps the install lib's contract — "one capsule, then install" —
//! intact rather than overloading it).
//!
//! ## Determinism
//!
//! Re-sealing identical inputs must produce identical bytes so a
//! `.shuttle` is reproducible and auditable. The packer therefore:
//! sorts entries by path, zeroes mtime, and normalizes mode (regular
//! files `0o644`, directories `0o755`). Gzip is written at a fixed
//! compression level with no embedded filename/mtime header.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};

/// Manifest filename inside a `.shuttle`.
pub(crate) const MANIFEST_NAME: &str = "Distro.toml";
/// Lockfile filename inside a `.shuttle`.
pub(crate) const LOCK_NAME: &str = "Distro.lock";
/// Signature filename inside a `.shuttle`.
pub(crate) const SIG_NAME: &str = "Distro.sig";
/// Subdirectory holding the packed capsules.
pub(crate) const CAPSULES_DIR: &str = "capsules";

/// Upper bound on a single unpacked `.shuttle` member (50 MB), matching
/// the capsule-download ceiling. Defends against decompression bombs.
const MAX_MEMBER_BYTES: u64 = 50 * 1024 * 1024;

/// A file to include in a `.shuttle`, addressed by its archive-relative
/// path. Bytes are owned so the packer can sort without re-reading.
pub(crate) struct ShuttleEntry {
    /// Archive-relative path (forward-slash, never absolute, no `..`).
    pub(crate) path: String,
    /// Raw file contents.
    pub(crate) bytes: Vec<u8>,
}

/// Pack `entries` into a deterministic gzipped tar at `out_path`.
///
/// Entries are sorted by path; every member gets mtime 0 and a
/// normalized mode. Re-running with identical inputs yields identical
/// output bytes.
pub(crate) fn pack(out_path: &Path, mut entries: Vec<ShuttleEntry>) -> anyhow::Result<()> {
    // Reject malformed archive-relative paths up front.
    for e in &entries {
        validate_archive_path(&e.path)?;
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let buf = Vec::new();
    // Fixed compression level, and `GzBuilder` with no filename/mtime so
    // the gzip header carries no environment-dependent bytes.
    let encoder = flate2::GzBuilder::new().write(buf, flate2::Compression::new(6));
    let mut tar = tar::Builder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);

    for entry in &entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(entry.bytes.len() as u64);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        tar.append_data(&mut header, &entry.path, entry.bytes.as_slice())
            .with_context(|| format!("failed to append {} to shuttle", entry.path))?;
    }

    let encoder = tar.into_inner().context("failed to finish tar stream")?;
    let compressed = encoder.finish().context("failed to finish gzip stream")?;

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(Path::new(".")))
        .context("failed to create temp file for shuttle")?;
    tmp.write_all(&compressed)
        .context("failed to write shuttle staging")?;
    tmp.persist(out_path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", out_path.display()))?;
    Ok(())
}

/// Unpack a `.shuttle` at `archive_path` into `dest` (a mirror dir),
/// WITHOUT installing anything.
///
/// Mirrors the hardened defense in the capsule unpacker: absolute paths
/// and `..` traversal are refused, symlinks and hard-links are refused,
/// and each member is size-capped. A malformed or truncated archive
/// yields a clean error.
pub(crate) fn unpack(archive_path: &Path, dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create mirror dir {}", dest.display()))?;

    let tar_gz = std::fs::File::open(archive_path)
        .with_context(|| format!("failed to open shuttle: {}", archive_path.display()))?;
    let tar = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);

    for entry in archive
        .entries()
        .context("failed to read shuttle entries (truncated or not a gzip tar?)")?
    {
        let mut entry = entry.context("failed to read shuttle entry (truncated archive?)")?;
        let entry_path = entry
            .path()
            .context("invalid path in shuttle")?
            .into_owned();

        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            bail!(
                "malicious shuttle detected: invalid path '{}'",
                entry_path.display()
            );
        }

        let et = entry.header().entry_type();
        if et.is_symlink() || et.is_hard_link() {
            bail!(
                "malicious shuttle detected: links are not allowed ('{}')",
                entry_path.display()
            );
        }
        // Skip directory entries — parents are created as needed below.
        if et.is_dir() {
            continue;
        }

        let size = entry.header().size().unwrap_or(0);
        if size > MAX_MEMBER_BYTES {
            bail!(
                "shuttle member '{}' is {size} bytes, exceeding the {MAX_MEMBER_BYTES}-byte limit",
                entry_path.display()
            );
        }

        let out_path = dest.join(&entry_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry
            .unpack(&out_path)
            .with_context(|| format!("failed to unpack {}", out_path.display()))?;
    }
    Ok(())
}

/// The archive-relative path of a capsule member: `capsules/<name>.capsule`.
pub(crate) fn capsule_member_path(name: &str) -> String {
    format!("{CAPSULES_DIR}/{name}.capsule")
}

/// The on-disk path of a capsule inside an unpacked mirror.
pub(crate) fn capsule_mirror_path(mirror: &Path, name: &str) -> PathBuf {
    mirror.join(CAPSULES_DIR).join(format!("{name}.capsule"))
}

/// Reject archive paths that are absolute, contain `..`, or are empty.
fn validate_archive_path(path: &str) -> anyhow::Result<()> {
    if path.is_empty() {
        bail!("empty archive path");
    }
    let p = Path::new(path);
    if p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("unsafe archive path '{path}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<ShuttleEntry> {
        vec![
            ShuttleEntry {
                path: SIG_NAME.to_string(),
                bytes: b"deadbeef".to_vec(),
            },
            ShuttleEntry {
                path: MANIFEST_NAME.to_string(),
                bytes: b"schema-version = 1\n".to_vec(),
            },
            ShuttleEntry {
                path: capsule_member_path("astrid-capsule-cli"),
                bytes: b"FAKE CAPSULE BYTES".to_vec(),
            },
        ]
    }

    #[test]
    fn pack_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.shuttle");
        let b = dir.path().join("b.shuttle");
        pack(&a, sample_entries()).unwrap();
        // Re-pack with entries in a different input order.
        let mut reordered = sample_entries();
        reordered.reverse();
        pack(&b, reordered).unwrap();
        let bytes_a = std::fs::read(&a).unwrap();
        let bytes_b = std::fs::read(&b).unwrap();
        assert_eq!(bytes_a, bytes_b, "re-seal must be byte-identical");
    }

    #[test]
    fn pack_then_unpack_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let shuttle = dir.path().join("d.shuttle");
        pack(&shuttle, sample_entries()).unwrap();

        let mirror = dir.path().join("mirror");
        unpack(&shuttle, &mirror).unwrap();

        assert_eq!(
            std::fs::read(mirror.join(MANIFEST_NAME)).unwrap(),
            b"schema-version = 1\n"
        );
        assert_eq!(std::fs::read(mirror.join(SIG_NAME)).unwrap(), b"deadbeef");
        assert_eq!(
            std::fs::read(capsule_mirror_path(&mirror, "astrid-capsule-cli")).unwrap(),
            b"FAKE CAPSULE BYTES"
        );
    }

    #[test]
    fn unpack_truncated_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let shuttle = dir.path().join("t.shuttle");
        pack(&shuttle, sample_entries()).unwrap();

        // Truncate to the first 10 bytes.
        let mut bytes = std::fs::read(&shuttle).unwrap();
        bytes.truncate(10);
        std::fs::write(&shuttle, &bytes).unwrap();

        let mirror = dir.path().join("mirror");
        let err = unpack(&shuttle, &mirror).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("truncated") || msg.contains("shuttle") || msg.contains("gzip"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_rejects_traversal() {
        assert!(validate_archive_path("../escape").is_err());
        assert!(validate_archive_path("/etc/passwd").is_err());
        assert!(validate_archive_path("").is_err());
        assert!(validate_archive_path("capsules/ok.capsule").is_ok());
    }
}
