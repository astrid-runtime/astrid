//! Validation and staging for a verified Station archive/lock handoff.
//!
//! Station remains the source authority and the daemon remains Astrid's only
//! durable installer. This boundary only accepts a private local archive plus
//! its exact typed lock, and proves that the bytes being handed off are the
//! bytes named by that lock before any Station provenance is persisted.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::Context;
use astrid_core::kernel_api::StationLock;
use sha2::{Digest as _, Sha256};

use super::station;

/// Bound untrusted handoff input to limit memory and parsing work.
const MAX_HANDOFF_LOCK_BYTES: u64 = 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Read and validate one untrusted lock file from the private handoff.
///
/// The sidecar digest is computed over the raw bytes Station wrote, before
/// parsing or canonicalization. This binds the lock crossing the subprocess
/// boundary to the verified lock selected by Station, rather than accepting a
/// different valid lock that happens to describe the same archive.
pub(crate) fn read_lock_file(path: &Path, expected_sha256: &str) -> anyhow::Result<StationLock> {
    validate_lock_sha256(expected_sha256)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read Station lock metadata at {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "Station lock must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_HANDOFF_LOCK_BYTES,
        "Station lock exceeds the 1 MiB handoff limit"
    );
    let bytes =
        fs::read(path).with_context(|| format!("read Station lock at {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_HANDOFF_LOCK_BYTES,
        "Station lock exceeds the 1 MiB handoff limit"
    );
    let actual_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    anyhow::ensure!(
        actual_sha256 == expected_sha256,
        "Station lock bytes disagree with the handoff SHA-256"
    );
    let mut lock: StationLock =
        serde_json::from_slice(&bytes).context("decode Station lock (expected station-lock-v2)")?;
    station::canonicalize_lock(&mut lock)?;
    station::validate_lock(&lock)?;
    Ok(lock)
}

/// Validate digest syntax before using it to authorize any sidecar read.
///
/// The handoff intentionally accepts only the exact lowercase wire form used
/// by Station so capitalization, bare hex, or another algorithm cannot silently
/// become an alternate binding convention.
pub(crate) fn validate_lock_sha256(value: &str) -> anyhow::Result<()> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("Station lock digest must use sha256:<64-hex>"))?;
    anyhow::ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Station lock digest must use sha256:<64-hex>"
    );
    Ok(())
}

/// Prove that an archive is exactly the artifact named by a Station lock.
///
/// Domain-specific manifest verification is retained in `station`; this
/// helper adds transport byte length, SHA-256, BLAKE3, and package identity so
/// a substituted archive cannot be persisted or sent to the daemon.
pub(crate) fn verify_archive_binding(archive: &Path, lock: &StationLock) -> anyhow::Result<()> {
    verify_archive_binding_at(archive, lock)
}

/// Copy and validate an archive into a private, create-new path. The daemon
/// receives this copy, so a mutation of the caller's original path after the
/// check cannot change the bytes that are installed.
pub(crate) fn stage_verified_archive(
    archive: &Path,
    lock: &StationLock,
) -> anyhow::Result<tempfile::NamedTempFile> {
    let metadata = regular_file_metadata(archive, "Station archive")?;
    anyhow::ensure!(
        metadata.len() <= station::MAX_ARTIFACT_BYTES,
        "Station archive exceeds the 64 MiB handoff limit"
    );
    anyhow::ensure!(
        metadata.len() == lock.artifact_size,
        "Station artifact size disagrees with the lock"
    );

    let mut staged = tempfile::Builder::new()
        .prefix("astrid-station-handoff-")
        .suffix(".capsule")
        .tempfile()
        .context("create private Station handoff archive")?;
    let mut input = File::open(archive)
        .with_context(|| format!("open Station archive at {}", archive.display()))?;
    copy_and_hash(&mut input, staged.as_file_mut(), lock)?;
    staged
        .as_file_mut()
        .sync_all()
        .context("sync private Station handoff archive")?;
    verify_archive_binding(staged.path(), lock)?;
    Ok(staged)
}

fn verify_archive_binding_at(archive: &Path, lock: &StationLock) -> anyhow::Result<()> {
    let metadata = regular_file_metadata(archive, "Station archive")?;
    anyhow::ensure!(
        metadata.len() <= station::MAX_ARTIFACT_BYTES,
        "Station archive exceeds the 64 MiB handoff limit"
    );
    anyhow::ensure!(
        metadata.len() == lock.artifact_size,
        "Station artifact size disagrees with the lock"
    );

    let mut input = File::open(archive)
        .with_context(|| format!("open Station archive at {}", archive.display()))?;
    let (actual_sha256, actual_blake3, total) = hash_archive(&mut input)?;
    anyhow::ensure!(
        total == lock.artifact_size,
        "Station artifact size changed while it was read"
    );
    anyhow::ensure!(
        actual_sha256 == lock.artifact_sha256,
        "Station artifact SHA-256 disagrees with the lock"
    );
    anyhow::ensure!(
        actual_blake3 == lock.artifact_blake3,
        "Station artifact BLAKE3 disagrees with the lock"
    );

    station::verify_manifest_digest(archive, lock)?;
    let manifest = astrid_capsule_install::read_archive_manifest(archive)
        .context("validate Station archive manifest")?;
    anyhow::ensure!(
        manifest.package.name == lock.coordinate.name,
        "Station lock capsule name disagrees with the archive manifest"
    );
    anyhow::ensure!(
        manifest.package.version == lock.version,
        "Station lock version disagrees with the archive manifest"
    );
    Ok(())
}

fn regular_file_metadata(path: &Path, label: &str) -> anyhow::Result<std::fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read {label} metadata at {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "{label} must be a regular file"
    );
    Ok(metadata)
}

fn hash_buffer() -> Box<[u8]> {
    vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice()
}

fn hash_archive(input: &mut File) -> anyhow::Result<(String, String, u64)> {
    let mut sha256 = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = hash_buffer();
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .context("read Station archive bytes")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("Station archive size overflow")?;
        anyhow::ensure!(
            total <= station::MAX_ARTIFACT_BYTES,
            "Station archive exceeds the 64 MiB handoff limit"
        );
        sha256.update(&buffer[..read]);
        blake3.update(&buffer[..read]);
    }
    Ok((
        format!("sha256:{}", hex::encode(sha256.finalize())),
        format!("blake3:{}", blake3.finalize().to_hex()),
        total,
    ))
}

fn copy_and_hash(input: &mut File, output: &mut File, lock: &StationLock) -> anyhow::Result<()> {
    let mut sha256 = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = hash_buffer();
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .context("read Station archive bytes")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("Station archive size overflow")?;
        anyhow::ensure!(
            total <= station::MAX_ARTIFACT_BYTES,
            "Station archive exceeds the 64 MiB handoff limit"
        );
        output
            .write_all(&buffer[..read])
            .context("write private Station handoff archive")?;
        sha256.update(&buffer[..read]);
        blake3.update(&buffer[..read]);
    }
    anyhow::ensure!(
        total == lock.artifact_size,
        "Station artifact size disagrees with the lock"
    );
    anyhow::ensure!(
        format!("sha256:{}", hex::encode(sha256.finalize())) == lock.artifact_sha256,
        "Station artifact SHA-256 disagrees with the lock"
    );
    anyhow::ensure!(
        format!("blake3:{}", blake3.finalize().to_hex()) == lock.artifact_blake3,
        "Station artifact BLAKE3 disagrees with the lock"
    );
    Ok(())
}

/// Validate the narrow CLI shape accepted for a Station handoff.
pub(crate) fn validate_cli_inputs(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
    station_lock_sha256: &str,
) -> anyhow::Result<()> {
    validate_lock_sha256(station_lock_sha256)?;
    anyhow::ensure!(
        capsule.is_none(),
        "--capsule cannot be combined with --station-lock"
    );
    anyhow::ensure!(
        !workspace,
        "--station-lock requires a daemon-owned user install, not --workspace"
    );
    let metadata = regular_file_metadata(Path::new(source), "Station handoff archive")?;
    anyhow::ensure!(
        metadata.len() <= station::MAX_ARTIFACT_BYTES,
        "Station archive exceeds the 64 MiB handoff limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn station_handoff_rejects_non_capsule_and_workspace_inputs() {
        let error = validate_cli_inputs("not-an-archive", None, false, DIGEST)
            .expect_err("missing local archive must fail closed");
        assert!(error.to_string().contains("handoff archive"));

        let error = validate_cli_inputs("fixture.capsule", None, true, DIGEST)
            .expect_err("workspace handoff must fail closed");
        assert!(error.to_string().contains("daemon-owned"));
    }

    #[test]
    fn station_handoff_rejects_capsule_selector() {
        let error = validate_cli_inputs("fixture.capsule", Some("demo"), false, DIGEST)
            .expect_err("multi-capsule selector must fail closed");
        assert!(error.to_string().contains("--capsule"));
    }

    #[test]
    fn station_handoff_digest_syntax_fails_before_file_io() {
        for value in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
            "sha256:000000000000000000000000000000000000000000000000000000000000000",
            &format!("sha256:{}", "A".repeat(64)),
        ] {
            assert!(validate_lock_sha256(value).is_err());
            assert!(
                read_lock_file(Path::new("/definitely/not/read"), value).is_err(),
                "malformed digest syntax must fail before sidecar access"
            );
        }
        assert!(validate_lock_sha256(DIGEST).is_ok());
    }

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn station_handoff_lock_size_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.lock.json");
        fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_HANDOFF_LOCK_BYTES + 1).unwrap()],
        )
        .unwrap();
        let error = read_lock_file(
            &path,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("oversized handoff lock was accepted");
        assert!(error.to_string().contains("1 MiB"));
    }
}
