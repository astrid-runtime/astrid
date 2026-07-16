//! Publisher authentication and integrity stages for self-managed updates.
//!
//! A release archive is not extractable until it has crossed both typed
//! boundaries in order: Sigstore authenticates the exact bytes and publisher,
//! then the release's BLAKE3 manifest independently checks transport integrity.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use sigstore_verify::trust_root::{TrustedRoot, TufConfig};
use sigstore_verify::types::Bundle;
use sigstore_verify::{VerificationPolicy, verify};

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const TRUST_ROOT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MANIFEST_LINE_BYTES: usize = 1_024;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct PublisherAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct IntegrityFailure(String);

/// Matchable self-update failure classes. Stage details remain internal while
/// the CLI receives a normal error only after the typed staging pipeline ends.
#[derive(Debug, thiserror::Error)]
pub(super) enum UpdateStageError {
    #[error("publisher authentication failed: {0}")]
    PublisherAuthentication(#[source] PublisherAuthenticationFailure),
    #[error("integrity check failed: {0}")]
    Integrity(#[source] IntegrityFailure),
    #[error(transparent)]
    Preparation(#[from] anyhow::Error),
}

impl UpdateStageError {
    pub(super) fn publisher(message: impl Into<String>) -> Self {
        Self::PublisherAuthentication(PublisherAuthenticationFailure(message.into()))
    }

    pub(super) fn integrity(message: impl Into<String>) -> Self {
        Self::Integrity(IntegrityFailure(message.into()))
    }
}

pub(super) fn publisher_bundle_download_error(error: &anyhow::Error) -> UpdateStageError {
    UpdateStageError::publisher(format!("could not download Sigstore bundle: {error}"))
}

pub(super) fn integrity_manifest_download_error(error: &anyhow::Error) -> UpdateStageError {
    UpdateStageError::integrity(format!("could not download BLAKE3SUMS.txt: {error}"))
}

/// Archive bytes whose Sigstore bundle authenticated the exact Astrid release
/// workflow and tag. Construction is private to this module.
#[derive(Debug)]
pub(super) struct PublisherAuthenticatedArchive(Vec<u8>);

/// Metadata bytes authenticated for one hard-coded Astrid workflow identity.
/// Construction remains private to this module so callers cannot supply a
/// different repository, workflow, ref, or issuer.
#[derive(Debug)]
pub(super) struct PublisherAuthenticatedMetadata(Vec<u8>);

impl PublisherAuthenticatedMetadata {
    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Archive bytes that also match their strict BLAKE3 release-manifest entry.
/// Extraction accepts this type rather than unverified bytes.
#[derive(Debug)]
pub(super) struct IntegrityVerifiedArchive(Vec<u8>);

#[cfg(test)]
impl IntegrityVerifiedArchive {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The one accepted keyless certificate identity for an Astrid release.
fn release_identity(version: &str) -> String {
    format!(
        "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/tags/v{version}"
    )
}

fn channel_identity() -> &'static str {
    "https://github.com/astrid-runtime/astrid/.github/workflows/promote-channel.yml@refs/heads/main"
}

fn parse_bundle(bundle_json: &[u8]) -> anyhow::Result<Bundle> {
    let text = std::str::from_utf8(bundle_json).context("bundle is not UTF-8")?;
    Bundle::from_json(text).context("bundle JSON is invalid")
}

fn parse_publisher_bundle(bundle_json: &[u8]) -> Result<Bundle, UpdateStageError> {
    parse_bundle(bundle_json).map_err(|_| UpdateStageError::publisher("malformed Sigstore bundle"))
}

fn verify_with_root(
    archive: &[u8],
    bundle: &Bundle,
    version: &str,
    root: &TrustedRoot,
) -> anyhow::Result<()> {
    let policy = VerificationPolicy::default()
        .require_identity(release_identity(version))
        .require_issuer(GITHUB_ACTIONS_ISSUER);
    verify(archive, bundle, &policy, root)
        .map(|_| ())
        .context("Sigstore evidence did not satisfy the release policy")
}

struct PublisherAuthenticator {
    root: TrustedRoot,
}

impl PublisherAuthenticator {
    async fn production() -> Result<Self, UpdateStageError> {
        let config = TufConfig::production().without_cache();
        let root = tokio::time::timeout(TRUST_ROOT_TIMEOUT, TrustedRoot::from_tuf(config))
            .await
            .map_err(|_| UpdateStageError::publisher("Sigstore trust refresh timed out"))?
            .map_err(|_| UpdateStageError::publisher("Sigstore trust refresh failed"))?;
        Ok(Self { root })
    }

    fn authenticate(
        &self,
        archive: Vec<u8>,
        bundle_json: &[u8],
        version: &str,
    ) -> Result<PublisherAuthenticatedArchive, UpdateStageError> {
        let bundle = parse_publisher_bundle(bundle_json)?;
        verify_with_root(&archive, &bundle, version, &self.root).map_err(|_| {
            UpdateStageError::publisher(
                "archive signature or exact release identity did not verify",
            )
        })?;
        Ok(PublisherAuthenticatedArchive(archive))
    }

    fn authenticate_metadata(
        &self,
        bytes: Vec<u8>,
        bundle_json: &[u8],
        identity: &str,
    ) -> Result<PublisherAuthenticatedMetadata, UpdateStageError> {
        let bundle = parse_publisher_bundle(bundle_json)?;
        let policy = VerificationPolicy::default()
            .require_identity(identity)
            .require_issuer(GITHUB_ACTIONS_ISSUER);
        verify(&bytes, &bundle, &policy, &self.root).map_err(|_| {
            UpdateStageError::publisher(
                "metadata signature or exact workflow identity did not verify",
            )
        })?;
        Ok(PublisherAuthenticatedMetadata(bytes))
    }
}

#[cfg(test)]
fn authenticate_for_test(
    archive: Vec<u8>,
    bundle_json: &[u8],
    identity: &str,
    issuer: &str,
    root: &TrustedRoot,
) -> Result<PublisherAuthenticatedArchive, UpdateStageError> {
    let bundle = parse_publisher_bundle(bundle_json)?;
    let policy = VerificationPolicy::default()
        .require_identity(identity)
        .require_issuer(issuer);
    verify(&archive, &bundle, &policy, root)
        .map_err(|_| UpdateStageError::publisher("archive signature or identity did not verify"))?;
    Ok(PublisherAuthenticatedArchive(archive))
}

/// Authenticate exact archive bytes against fresh, TUF-verified Sigstore
/// public-good trust material. There is deliberately no stale/offline fallback
/// and no caller-supplied identity, issuer, or trust-root override.
pub(super) async fn authenticate_archive(
    archive: Vec<u8>,
    bundle_json: &[u8],
    version: &str,
) -> Result<PublisherAuthenticatedArchive, UpdateStageError> {
    PublisherAuthenticator::production()
        .await?
        .authenticate(archive, bundle_json, version)
}

/// Authenticate a channel pointer only for Astrid's promotion workflow on
/// `main`. The identity is not caller-configurable.
pub(super) struct MetadataAuthenticator(PublisherAuthenticator);

impl MetadataAuthenticator {
    /// Refresh the public-good trust root once for all metadata in this update
    /// resolution. Reusing that fresh root within one operation avoids a
    /// second network refresh without admitting a stale/offline fallback.
    pub(super) async fn production() -> Result<Self, UpdateStageError> {
        PublisherAuthenticator::production().await.map(Self)
    }

    pub(super) fn authenticate_channel_pointer(
        &self,
        bytes: Vec<u8>,
        bundle_json: &[u8],
    ) -> Result<PublisherAuthenticatedMetadata, UpdateStageError> {
        self.0
            .authenticate_metadata(bytes, bundle_json, channel_identity())
    }

    /// Authenticate an immutable release manifest for the exact version tag.
    /// The identity is derived from a canonical version, never from metadata.
    pub(super) fn authenticate_release_manifest(
        &self,
        bytes: Vec<u8>,
        bundle_json: &[u8],
        version: &str,
    ) -> Result<PublisherAuthenticatedMetadata, UpdateStageError> {
        self.0
            .authenticate_metadata(bytes, bundle_json, &release_identity(version))
    }
}

/// Verify the authenticated archive against the one canonical BLAKE3 entry for
/// `asset_name`. Manifest parsing is global: malformed or duplicate entries for
/// another platform invalidate the release too.
pub(super) fn verify_integrity(
    archive: PublisherAuthenticatedArchive,
    sums_body: &str,
    asset_name: &str,
    channel_blake3: Option<&str>,
) -> Result<IntegrityVerifiedArchive, UpdateStageError> {
    let mut expected = None;
    let mut seen_assets = HashSet::new();

    for (index, line) in sums_body.lines().enumerate() {
        let line_number = index
            .checked_add(1)
            .ok_or_else(|| UpdateStageError::integrity("BLAKE3SUMS.txt contains too many lines"))?;
        if line.len() > MAX_MANIFEST_LINE_BYTES {
            return Err(UpdateStageError::integrity(format!(
                "BLAKE3SUMS.txt line {line_number} exceeds {MAX_MANIFEST_LINE_BYTES} byte limit"
            )));
        }
        let (hex, name) = line.split_once("  ").ok_or_else(|| {
            UpdateStageError::integrity(format!(
                "malformed BLAKE3SUMS.txt line {line_number}: expected '<digest>  <asset>'"
            ))
        })?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateStageError::integrity(format!(
                "malformed BLAKE3 digest on line {line_number}: expected 64 lowercase hex characters"
            )));
        }
        if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(UpdateStageError::integrity(format!(
                "malformed BLAKE3SUMS.txt asset name on line {line_number}"
            )));
        }
        if !seen_assets.insert(name) {
            return Err(UpdateStageError::integrity(format!(
                "duplicate checksum for '{name}' in BLAKE3SUMS.txt"
            )));
        }

        let digest = blake3::Hash::from_hex(hex).map_err(|_| {
            UpdateStageError::integrity(format!("invalid BLAKE3 digest on line {line_number}"))
        })?;
        if name == asset_name {
            expected = Some(digest);
        }
    }

    let expected = expected.ok_or_else(|| {
        UpdateStageError::integrity(format!("no checksum for '{asset_name}' in BLAKE3SUMS.txt"))
    })?;
    if let Some(channel_blake3) = channel_blake3 {
        let channel_digest = blake3::Hash::from_hex(channel_blake3).map_err(|_| {
            UpdateStageError::integrity("signed channel contains an invalid BLAKE3 digest")
        })?;
        if channel_digest != expected {
            return Err(UpdateStageError::integrity(format!(
                "BLAKE3SUMS.txt does not match the signed channel digest for '{asset_name}'"
            )));
        }
    }
    let actual = blake3::hash(&archive.0);
    if actual != expected {
        return Err(UpdateStageError::integrity(format!(
            "checksum mismatch for '{asset_name}': expected {}, got {}",
            expected.to_hex(),
            actual.to_hex()
        )));
    }

    Ok(IntegrityVerifiedArchive(archive.0))
}

/// Extract bytes only after publisher authentication and integrity verification
/// have both succeeded.
pub(super) fn extract_verified_archive(
    archive: IntegrityVerifiedArchive,
    asset_name: &str,
    extracted_dir_name: &str,
) -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
    extract_verified_archive_with(archive, asset_name, extracted_dir_name, tempfile::tempdir)
}

fn extract_verified_archive_with<F>(
    archive: IntegrityVerifiedArchive,
    asset_name: &str,
    extracted_dir_name: &str,
    make_temp_dir: F,
) -> anyhow::Result<(tempfile::TempDir, PathBuf)>
where
    F: FnOnce() -> std::io::Result<tempfile::TempDir>,
{
    let IntegrityVerifiedArchive(archive_bytes) = archive;
    let tmp_dir = make_temp_dir()?;
    let archive_path = tmp_dir.path().join(asset_name);
    std::fs::write(&archive_path, archive_bytes)?;
    let tar_gz = std::fs::File::open(&archive_path)?;
    let decoder = flate2::read::GzDecoder::new(tar_gz);
    let mut tar = tar::Archive::new(decoder);
    tar.unpack(tmp_dir.path())?;

    let extract_dir = tmp_dir.path().join(extracted_dir_name);
    Ok((tmp_dir, extract_dir))
}

#[cfg(test)]
#[path = "update_auth_tests.rs"]
mod tests;
