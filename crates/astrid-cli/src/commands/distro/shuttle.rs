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

/// Whether a member of `len` bytes is within the per-member size cap.
///
/// Pulled out as a pure predicate so the boundary is unit-testable and the
/// pack/unpack paths share one definition of "too big".
fn within_member_limit(len: u64) -> bool {
    len <= MAX_MEMBER_BYTES
}

/// The payload of a [`ShuttleEntry`]: either in-memory bytes (for the
/// small manifest/lock/sig members) or a path to a staged file streamed
/// in at pack time (for capsules, which are already on disk and can be up
/// to 50 MB each — buffering them all in RAM risks OOM).
pub(crate) enum ShuttleContent {
    /// Owned in-memory bytes (small members, or test fixtures).
    Bytes(Vec<u8>),
    /// A source file on disk, streamed into the tar at pack time.
    File(PathBuf),
}

/// A file to include in a `.shuttle`, addressed by its archive-relative
/// path. Content is either owned bytes or a staged file path so large
/// capsules need never be held fully in memory.
pub(crate) struct ShuttleEntry {
    /// Archive-relative path (forward-slash, never absolute, no `..`).
    pub(crate) path: String,
    /// The member's content source.
    pub(crate) content: ShuttleContent,
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

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    // Write the gzip stream DIRECTLY into the output temp file rather than
    // buffering the whole compressed archive in memory. `File` members are
    // streamed from disk into the tar (`append_data` copies from the reader),
    // so nothing larger than a copy buffer is ever resident at once.
    let mut tmp = tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(Path::new(".")))
        .context("failed to create temp file for shuttle")?;

    {
        // Fixed compression level, and `GzBuilder` with no filename/mtime so
        // the gzip header carries no environment-dependent bytes.
        let encoder =
            flate2::GzBuilder::new().write(tmp.as_file_mut(), flate2::Compression::new(6));
        let mut tar = tar::Builder::new(encoder);
        tar.mode(tar::HeaderMode::Deterministic);

        for entry in &entries {
            let mut header = tar::Header::new_gnu();
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);

            match &entry.content {
                ShuttleContent::Bytes(bytes) => {
                    header.set_size(bytes.len() as u64);
                    header.set_cksum();
                    tar.append_data(&mut header, &entry.path, bytes.as_slice())
                        .with_context(|| format!("failed to append {} to shuttle", entry.path))?;
                },
                ShuttleContent::File(src) => {
                    let metadata = std::fs::metadata(src).with_context(|| {
                        format!("failed to stat staged capsule {}", src.display())
                    })?;
                    if !within_member_limit(metadata.len()) {
                        bail!(
                            "shuttle member '{}' is {} bytes ({}), exceeding the \
                             {MAX_MEMBER_BYTES}-byte per-member limit",
                            src.display(),
                            metadata.len(),
                            entry.path
                        );
                    }
                    header.set_size(metadata.len());
                    header.set_cksum();
                    let mut file = std::fs::File::open(src).with_context(|| {
                        format!("failed to open staged capsule {}", src.display())
                    })?;
                    tar.append_data(&mut header, &entry.path, &mut file)
                        .with_context(|| format!("failed to append {} to shuttle", entry.path))?;
                },
            }
        }

        let encoder = tar.into_inner().context("failed to finish tar stream")?;
        encoder.finish().context("failed to finish gzip stream")?;
    }

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
        // Everything that survives to here must be an ordinary file. Device
        // nodes, FIFOs, sockets, and any other special entry type are
        // rejected: a `.shuttle` only ever legitimately carries regular
        // files, so an exotic type is either corruption or an attack.
        if !et.is_file() {
            bail!(
                "malicious shuttle detected: unsupported entry type for '{}' \
                 (only regular files are allowed)",
                entry_path.display()
            );
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
                content: ShuttleContent::Bytes(b"deadbeef".to_vec()),
            },
            ShuttleEntry {
                path: MANIFEST_NAME.to_string(),
                content: ShuttleContent::Bytes(b"schema-version = 1\n".to_vec()),
            },
            ShuttleEntry {
                path: capsule_member_path("astrid-capsule-cli"),
                content: ShuttleContent::Bytes(b"FAKE CAPSULE BYTES".to_vec()),
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
    fn file_and_bytes_entries_roundtrip_identically() {
        // A `File` capsule entry must pack byte-for-byte the same as the
        // equivalent in-memory `Bytes` entry (streaming changes nothing the
        // archive observes).
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("astrid-capsule-cli.capsule");
        std::fs::write(&staged, b"FAKE CAPSULE BYTES").unwrap();

        let from_file = dir.path().join("file.shuttle");
        pack(
            &from_file,
            vec![
                ShuttleEntry {
                    path: SIG_NAME.to_string(),
                    content: ShuttleContent::Bytes(b"deadbeef".to_vec()),
                },
                ShuttleEntry {
                    path: MANIFEST_NAME.to_string(),
                    content: ShuttleContent::Bytes(b"schema-version = 1\n".to_vec()),
                },
                ShuttleEntry {
                    path: capsule_member_path("astrid-capsule-cli"),
                    content: ShuttleContent::File(staged),
                },
            ],
        )
        .unwrap();

        let from_bytes = dir.path().join("bytes.shuttle");
        pack(&from_bytes, sample_entries()).unwrap();

        assert_eq!(
            std::fs::read(&from_file).unwrap(),
            std::fs::read(&from_bytes).unwrap(),
            "a streamed File entry must pack identically to in-memory Bytes"
        );

        // And it still unpacks to the original capsule bytes.
        let mirror = dir.path().join("mirror");
        unpack(&from_file, &mirror).unwrap();
        assert_eq!(
            std::fs::read(capsule_mirror_path(&mirror, "astrid-capsule-cli")).unwrap(),
            b"FAKE CAPSULE BYTES"
        );
    }

    #[test]
    fn validate_rejects_traversal() {
        assert!(validate_archive_path("../escape").is_err());
        assert!(validate_archive_path("/etc/passwd").is_err());
        assert!(validate_archive_path("").is_err());
        assert!(validate_archive_path("capsules/ok.capsule").is_ok());
    }

    #[test]
    fn within_member_limit_boundary() {
        // At the cap is allowed; one byte over is not.
        assert!(within_member_limit(MAX_MEMBER_BYTES));
        assert!(within_member_limit(MAX_MEMBER_BYTES - 1));
        assert!(within_member_limit(0));
        assert!(!within_member_limit(MAX_MEMBER_BYTES + 1));
    }

    #[test]
    fn unpack_rejects_non_regular_entry() {
        // Hand-build a gzipped tar whose single member is a FIFO (a
        // non-regular entry). `unpack` must refuse it rather than try to
        // materialize a special file.
        let dir = tempfile::tempdir().unwrap();
        let shuttle = dir.path().join("fifo.shuttle");

        {
            let file = std::fs::File::create(&shuttle).unwrap();
            let encoder = flate2::GzBuilder::new().write(file, flate2::Compression::new(6));
            let mut tar = tar::Builder::new(encoder);

            let mut header = tar::Header::new_gnu();
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_size(0);
            header.set_entry_type(tar::EntryType::fifo());
            header.set_cksum();
            tar.append_data(&mut header, "capsules/evil.capsule", std::io::empty())
                .unwrap();

            let encoder = tar.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        let mirror = dir.path().join("mirror");
        let err = unpack(&shuttle, &mirror).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unsupported entry type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pack_rejects_oversized_file_member() {
        // A staged `File` member larger than the per-member cap must be
        // rejected at pack time, naming the file. Use a sparse file so we
        // don't actually write 50 MB to disk.
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("astrid-capsule-cli.capsule");
        let f = std::fs::File::create(&staged).unwrap();
        f.set_len(MAX_MEMBER_BYTES + 1).unwrap();
        drop(f);

        let out = dir.path().join("over.shuttle");
        let err = pack(
            &out,
            vec![ShuttleEntry {
                path: capsule_member_path("astrid-capsule-cli"),
                content: ShuttleContent::File(staged.clone()),
            }],
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("per-member limit"), "unexpected error: {err}");
        assert!(
            msg.contains(&staged.display().to_string()),
            "error should name the offending file: {err}"
        );
    }
}
