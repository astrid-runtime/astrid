//! Capsule Index resolution and verified-artifact installation.
//!
//! This module deliberately owns only the seam between the Index client and
//! the existing archive installer. The client supplies a protocol
//! `PublicationRecord`/`LockRecord` pair plus artifact bytes; this module
//! checks those bindings and the artifact digest before invoking the ordinary
//! unpack/install transaction. An explicit Index request never falls back to
//! GitHub or a different Index.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule_index::{Coordinate, LockRecord, MirrorUrl, PublicationRecord};
use astrid_capsule_index_client::{ClientConfig, IndexClient as ProtocolIndexClient};
use astrid_capsule_index_tuf::TrustConfig;
use astrid_capsule_install::{CapsuleMeta, IndexInstallProvenance, read_meta, write_meta};
use astrid_core::dirs::AstridHome;
use async_trait::async_trait;
use semver::VersionReq;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use url::Url;

use crate::commands::index::{IndexSource, IndexStore, ReqwestTufTransport};

use super::install::{InstalledCapsuleOutcome, ManualInstallOptions, unpack_via_lib};

/// A verified artifact returned by an Index client.
#[derive(Debug, Clone)]
pub(crate) enum IndexArtifact {
    /// A path in the client's cache. The installer still snapshots and
    /// verifies its bytes before using it, closing path replacement races.
    Path(PathBuf),
    /// Artifact bytes already held by the client.
    Bytes(Vec<u8>),
}

/// Result of resolving one coordinate through a trusted Index source.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedIndexArtifact {
    /// Sealed publication metadata.
    pub(crate) record: PublicationRecord,
    /// Complete lock binding for the selected publication.
    pub(crate) lock: LockRecord,
    /// Artifact bytes or a cache path supplied by the client.
    pub(crate) artifact: IndexArtifact,
    /// Non-fatal client warnings, such as a yanked publication.
    pub(crate) warnings: Vec<String>,
}

/// Narrow async seam implemented by the forthcoming Index client.
#[async_trait]
pub(crate) trait IndexClient: Send + Sync {
    /// Resolve and fetch one verified publication artifact.
    async fn resolve_and_fetch(
        &self,
        index: &IndexSource,
        coordinate: &Coordinate,
        requirement: Option<&VersionReq>,
        existing_lock: Option<&LockRecord>,
    ) -> anyhow::Result<VerifiedIndexArtifact>;
}

/// Transitional client used until dispatch wires the production client.
/// It fails closed rather than guessing a GitHub source or inventing an
/// unverified artifact.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnavailableIndexClient;

#[async_trait]
impl IndexClient for UnavailableIndexClient {
    async fn resolve_and_fetch(
        &self,
        index: &IndexSource,
        _coordinate: &Coordinate,
        _requirement: Option<&VersionReq>,
        _existing_lock: Option<&LockRecord>,
    ) -> anyhow::Result<VerifiedIndexArtifact> {
        bail!(
            "Index client is not wired for source '{}'; refusing unverified install",
            index.id
        )
    }
}

/// Production anonymous client adapter for the CLI install/update seam.
///
/// TUF metadata and publication records are resolved only through the
/// configured source identity. Artifact locations are transport hints inside
/// the already-verified publication; every response is bounded, redirect hops
/// are revalidated, and the sealed protocol digest is checked before returning
/// bytes.
#[derive(Debug, Clone)]
pub(crate) struct ProductionIndexClient {
    state_root: PathBuf,
    transport: ReqwestTufTransport,
}

impl ProductionIndexClient {
    /// Construct an adapter whose TUF high-water/cache state is private to the
    /// supplied Astrid home.
    pub(crate) fn for_home(home_root: &Path) -> anyhow::Result<Self> {
        let transport = ReqwestTufTransport::new(64 * 1024 * 1024)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(Self {
            state_root: home_root.join("var").join("capsule-index"),
            transport,
        })
    }

    fn trust_config(&self, index: &IndexSource) -> anyhow::Result<(TrustConfig, PathBuf)> {
        let identity = index.protocol_identity()?;
        let root_bytes = index.root.bytes()?;
        let base_url = Url::parse(&index.base_url)
            .with_context(|| format!("parse configured Index URL '{}'", index.base_url))?;
        let state_dir = self.state_root.join(&index.id);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create Index state directory {}", state_dir.display()))?;
        #[cfg(unix)]
        std::fs::set_permissions(
            &state_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .with_context(|| format!("protect Index state directory {}", state_dir.display()))?;
        let trust = TrustConfig::new(
            identity,
            root_bytes,
            base_url.clone(),
            base_url,
            // Share the exact high-water state/datastore paths used by
            // `astrid index update`; the TUF crate's state lock then
            // serializes metadata refreshes across both command paths.
            state_dir.join("trusted-state.json"),
            state_dir.join("metadata"),
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let cache = state_dir.join("objects");
        Ok((trust, cache))
    }

    async fn fetch_artifact(
        &self,
        record: &PublicationRecord,
        locations: &[MirrorUrl],
    ) -> anyhow::Result<Vec<u8>> {
        const MAX_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;
        let expected_size = record.artifact().size();
        anyhow::ensure!(
            expected_size <= MAX_ARTIFACT_BYTES,
            "Index artifact exceeds 50 MB install limit ({expected_size} bytes)"
        );
        let limit = usize::try_from(expected_size.max(1))?;
        let mut failures = Vec::new();
        for location in locations {
            let url = Url::parse(location.as_str())
                .with_context(|| format!("parse sealed artifact URL {location}"))?;
            match self.transport.download_bytes(&url, limit).await {
                Ok(bytes) => {
                    if bytes.len() as u64 != expected_size {
                        failures.push(format!(
                            "{location}: size mismatch (expected {expected_size}, got {})",
                            bytes.len()
                        ));
                        continue;
                    }
                    // Verify once at the network boundary as well as in the
                    // install seam, so a client caller can never observe
                    // unbound artifact bytes.
                    verified_artifact_bytes(record, &IndexArtifact::Bytes(bytes.clone()))?;
                    return Ok(bytes);
                },
                Err(error) => failures.push(format!("{location}: {error}")),
            }
        }
        bail!(
            "all sealed artifact locations failed for {}: {}",
            record.key(),
            failures.join("; ")
        )
    }
}

#[async_trait]
impl IndexClient for ProductionIndexClient {
    async fn resolve_and_fetch(
        &self,
        index: &IndexSource,
        coordinate: &Coordinate,
        requirement: Option<&VersionReq>,
        existing_lock: Option<&LockRecord>,
    ) -> anyhow::Result<VerifiedIndexArtifact> {
        let (trust, cache_root) = self.trust_config(index)?;
        let client = ProtocolIndexClient::new(ClientConfig::new(trust, cache_root));
        let requirement = requirement.cloned().unwrap_or(VersionReq::STAR);
        // Preserve a yanked existing lock only when it still satisfies the
        // caller's requested range. An explicit request for a different
        // version must resolve that version instead of being trapped by the
        // prior lock; updates use `STAR` and intentionally select latest.
        let matching_lock =
            existing_lock.filter(|lock| requirement.matches(lock.version().as_version()));
        let resolved =
            if let Some(lock) = matching_lock.filter(|_| requirement != VersionReq::STAR) {
                client
                    .resolve_with_lock(self.transport.clone(), coordinate, &requirement, lock)
                    .await
            } else {
                client
                    .resolve(self.transport.clone(), coordinate, &requirement)
                    .await
            }
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let identity = client.identity().clone();
        let lock = LockRecord::from_publication(&identity, &resolved.record);
        let mut warnings = Vec::new();
        if resolved.state.is_yanked() {
            warnings.push(
                "selected publication is yanked but retained by the existing lock".to_owned(),
            );
        }
        if resolved.state.is_deprecated() {
            warnings.push("selected publication is deprecated".to_owned());
        }
        let bytes = self
            .fetch_artifact(&resolved.record, &resolved.artifact_locations)
            .await?;
        Ok(VerifiedIndexArtifact {
            record: resolved.record,
            lock,
            artifact: IndexArtifact::Bytes(bytes),
            warnings,
        })
    }
}

/// Install one capsule through an injected Index client using Astrid's
/// resolved home. This is the command-independent entry point used by CLI
/// dispatch and hermetic tests.
pub(super) async fn install_from_index<C: IndexClient + ?Sized>(
    source: &str,
    index_id: &str,
    workspace: bool,
    prompt: &ManualInstallOptions,
    client: &C,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let home = AstridHome::resolve()?;
    let principal = crate::principal::current();
    install_from_index_with_home(
        source, index_id, workspace, &home, &principal, prompt, client,
    )
    .await
}

/// Testable Index install entry point with an injected home/principal.
pub(super) async fn install_from_index_with_home<C: IndexClient + ?Sized>(
    source: &str,
    index_id: &str,
    workspace: bool,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
    client: &C,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let (coordinate, requirement) = parse_coordinate_request(source)?;
    let store = IndexStore::from_home(home.root(), None);
    let index = store
        .load()?
        .into_iter()
        .find(|candidate| candidate.id == index_id)
        .ok_or_else(|| anyhow::anyhow!("Index source not found: {index_id}"))?;
    anyhow::ensure!(
        index.enabled,
        "Index source '{}' is disabled; enable it before resolution",
        index.id
    );

    let existing_lock = existing_index_lock(home, principal, &coordinate, workspace)?;
    let verified = client
        .resolve_and_fetch(
            &index,
            &coordinate,
            requirement.as_ref(),
            existing_lock.as_ref(),
        )
        .await
        .context("Index resolution or artifact verification failed")?;
    validate_verified_result(&index, &coordinate, requirement.as_ref(), &verified)?;
    for warning in &verified.warnings {
        eprintln!("warning: Index source {index_id}: {warning}");
    }

    // Snapshot bytes into a private temporary archive after verification. A
    // cache-path result may be replaced after the client returns; installing
    // this snapshot guarantees the bytes we checked are the bytes unpacked.
    let temp_dir = tempfile::tempdir().context("create Index artifact staging directory")?;
    let archive = temp_dir.path().join("verified.capsule");
    let bytes = verified_artifact_bytes(&verified.record, &verified.artifact)?;
    std::fs::write(&archive, &bytes).context("stage verified Index artifact")?;

    let expected_id = CapsuleId::new(verified.record.coordinate().name.as_str())?;
    let expected_version = verified.record.version().to_string();
    let installed = unpack_via_lib(
        &archive,
        workspace,
        home,
        Some(source),
        principal,
        Some(super::install::ExpectedCapsule {
            id: &expected_id,
            version: Some(&expected_version),
        }),
        prompt,
    )?;
    stamp_index_provenance(
        home,
        principal,
        workspace,
        &installed,
        &index,
        verified.lock,
    )?;
    Ok(installed)
}

fn parse_coordinate_request(source: &str) -> anyhow::Result<(Coordinate, Option<VersionReq>)> {
    let (coordinate, suffix) = super::install::split_version_suffix(source);
    let coordinate = coordinate
        .parse::<Coordinate>()
        .map_err(|error| anyhow::anyhow!("invalid Index coordinate {coordinate:?}: {error}"))?;
    let requirement = suffix
        .map(|version| {
            VersionReq::parse(&format!("={version}"))
                .with_context(|| format!("invalid Index version requirement {version:?}"))
        })
        .transpose()?;
    Ok((coordinate, requirement))
}

fn existing_index_lock(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    coordinate: &Coordinate,
    workspace: bool,
) -> anyhow::Result<Option<LockRecord>> {
    let target = astrid_capsule_install::resolve_target_dir_for_with_layout(
        home,
        principal,
        coordinate.name.as_str(),
        workspace,
        crate::workspace_layout::current(),
    )?;
    Ok(read_meta(&target).and_then(|meta| {
        meta.index_provenance
            .filter(|provenance| provenance.lock.coordinate() == coordinate)
            .map(|provenance| provenance.lock)
    }))
}

fn validate_verified_result(
    index: &IndexSource,
    coordinate: &Coordinate,
    requirement: Option<&VersionReq>,
    verified: &VerifiedIndexArtifact,
) -> anyhow::Result<()> {
    let identity = index.protocol_identity()?;
    anyhow::ensure!(
        verified.record.index_id() == &identity.id,
        "Index client returned publication for '{}', requested '{}'",
        verified.record.index_id(),
        identity.id
    );
    verified.lock.verify(&identity, &verified.record)?;
    anyhow::ensure!(
        verified.record.coordinate() == coordinate,
        "Index client returned coordinate {}, requested {}",
        verified.record.coordinate(),
        coordinate
    );
    if let Some(requirement) = requirement {
        anyhow::ensure!(
            requirement.matches(verified.record.version().as_version()),
            "Index publication version {} does not satisfy {requirement}",
            verified.record.version()
        );
    }
    Ok(())
}

/// Ensure an installed Index provenance record still resolves to the exact
/// configured URL and trust-root identity it was installed from. Updates must
/// not silently follow a re-pointed source with the same display ID.
pub(super) fn validate_existing_index_provenance(
    index: &IndexSource,
    provenance: &IndexInstallProvenance,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        index.base_url == provenance.base_url,
        "Index '{}' base URL changed from '{}' to '{}'; refusing update",
        index.id,
        provenance.base_url,
        index.base_url
    );
    let identity = index.protocol_identity()?;
    anyhow::ensure!(
        provenance.lock.index_id() == &identity.id,
        "Index provenance identity '{}' does not match configured source '{}'",
        provenance.lock.index_id(),
        identity.id
    );
    anyhow::ensure!(
        provenance.lock.trust_root() == &identity.trust_root,
        "Index '{}' trust root changed; explicit root rotation is required before update",
        index.id
    );
    Ok(())
}

fn verified_artifact_bytes(
    record: &PublicationRecord,
    artifact: &IndexArtifact,
) -> anyhow::Result<Vec<u8>> {
    let bytes = match artifact {
        IndexArtifact::Bytes(bytes) => bytes.clone(),
        IndexArtifact::Path(path) => {
            let metadata = std::fs::metadata(path)
                .with_context(|| format!("read Index artifact metadata {}", path.display()))?;
            anyhow::ensure!(
                metadata.is_file(),
                "Index artifact path is not a regular file: {}",
                path.display()
            );
            anyhow::ensure!(
                metadata.len() <= 50 * 1024 * 1024,
                "Index artifact exceeds 50 MB install limit"
            );
            let file = std::fs::File::open(path)
                .with_context(|| format!("open Index artifact {}", path.display()))?;
            let mut bytes = Vec::new();
            file.take(50 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("read Index artifact {}", path.display()))?;
            anyhow::ensure!(
                bytes.len() <= 50 * 1024 * 1024,
                "Index artifact exceeds 50 MB install limit"
            );
            bytes
        },
    };
    anyhow::ensure!(
        bytes.len() as u64 == record.artifact().size(),
        "Index artifact size mismatch: expected {}, got {}",
        record.artifact().size(),
        bytes.len()
    );
    // A publication may carry a digest set (for example SHA-256 plus
    // BLAKE3). Every sealed digest is part of the immutable record binding;
    // accepting only one would let a corrupted alternate digest pass while
    // the caller happened to verify the other algorithm.
    let matched = !record.artifact().digests().is_empty()
        && record.artifact().digests().iter().all(|expected| {
            let actual = match expected.algorithm() {
                astrid_capsule_index::DigestAlgorithm::Sha256 => {
                    astrid_capsule_index::Digest::from_bytes(
                        expected.algorithm(),
                        Sha256::digest(&bytes),
                    )
                },
                astrid_capsule_index::DigestAlgorithm::Sha384 => {
                    astrid_capsule_index::Digest::from_bytes(
                        expected.algorithm(),
                        Sha384::digest(&bytes),
                    )
                },
                astrid_capsule_index::DigestAlgorithm::Sha512 => {
                    astrid_capsule_index::Digest::from_bytes(
                        expected.algorithm(),
                        Sha512::digest(&bytes),
                    )
                },
                astrid_capsule_index::DigestAlgorithm::Blake3 => {
                    Ok(astrid_capsule_index::Digest::blake3(&bytes))
                },
            };
            actual.is_ok_and(|actual| actual == *expected)
        });
    anyhow::ensure!(
        matched,
        "Index artifact digest does not match the sealed publication"
    );
    Ok(bytes)
}

fn stamp_index_provenance(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    workspace: bool,
    installed: &InstalledCapsuleOutcome,
    index: &IndexSource,
    lock: LockRecord,
) -> anyhow::Result<()> {
    let target = astrid_capsule_install::resolve_target_dir_for_with_layout(
        home,
        principal,
        installed.id.as_str(),
        workspace,
        crate::workspace_layout::current(),
    )?;
    let mut meta: CapsuleMeta = read_meta(&target).ok_or_else(|| {
        anyhow::anyhow!("installed capsule metadata is missing after Index install")
    })?;
    meta.index_provenance = Some(IndexInstallProvenance {
        base_url: index.base_url.clone(),
        lock,
    });
    write_meta(&target, &meta)
}

/// Re-exported for focused tests that need to validate artifact bindings
/// without invoking the filesystem installer.
pub(crate) fn verify_index_artifact_bytes(
    record: &PublicationRecord,
    bytes: &[u8],
) -> anyhow::Result<()> {
    verified_artifact_bytes(record, &IndexArtifact::Bytes(bytes.to_vec())).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capsule_index::{
        Digest, DigestAlgorithm, IndexId, IndexIdentity, TrustRootFingerprint,
    };

    fn root_fingerprint(bytes: &[u8]) -> TrustRootFingerprint {
        TrustRootFingerprint::new(
            Digest::from_bytes(DigestAlgorithm::Sha256, Sha256::digest(bytes)).unwrap(),
        )
    }

    fn source() -> IndexSource {
        let fingerprint = root_fingerprint(b"test-root");
        IndexSource {
            id: "third-party".to_string(),
            base_url: "https://index.example/".to_string(),
            root: crate::commands::index::PinnedRoot {
                bytes_b64: String::new(),
                path: None,
                fingerprint: fingerprint.to_string(),
            },
            enabled: true,
            priority: 100,
            built_in: false,
            metadata: None,
        }
    }

    #[test]
    fn parses_coordinate_and_exact_version_suffix() {
        let (coordinate, requirement) = parse_coordinate_request("@scope/demo@1.2.3").unwrap();
        assert_eq!(coordinate.to_string(), "@scope/demo");
        assert!(
            requirement
                .as_ref()
                .is_some_and(|requirement| requirement.matches(&semver::Version::new(1, 2, 3)))
        );
        assert!(parse_coordinate_request("scope/demo").is_err());
        assert!(parse_coordinate_request("@scope/demo@not-semver").is_err());
    }

    #[test]
    fn tampered_artifact_is_rejected_before_unpack() {
        let record: PublicationRecord = serde_json::from_str(include_str!(
            "../../../../astrid-capsule-index/tests/fixtures/valid-publication.json"
        ))
        .unwrap();
        let tampered = vec![0_u8; record.artifact().size() as usize];
        let error = verify_index_artifact_bytes(&record, &tampered).unwrap_err();
        assert!(error.to_string().contains("digest"));
    }

    #[tokio::test]
    async fn explicit_index_client_failure_does_not_fallback() {
        let index = source();
        let coordinate = "@scope/demo".parse::<Coordinate>().unwrap();
        let error = UnavailableIndexClient
            .resolve_and_fetch(&index, &coordinate, None, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refusing unverified install"));
    }

    #[test]
    fn provenance_rejects_root_or_url_repointing() {
        let index = source();
        let identity = IndexIdentity::new(
            IndexId::new(index.id.clone()).unwrap(),
            root_fingerprint(b"test-root"),
        );
        let record: PublicationRecord = serde_json::from_str(include_str!(
            "../../../../astrid-capsule-index/tests/fixtures/valid-publication.json"
        ))
        .unwrap();
        let lock = LockRecord::from_publication(&identity, &record);
        let provenance = IndexInstallProvenance {
            base_url: index.base_url.clone(),
            lock,
        };
        assert!(validate_existing_index_provenance(&index, &provenance).is_ok());

        let mut changed_url = index.clone();
        changed_url.base_url = "https://mirror.example/".to_string();
        assert!(validate_existing_index_provenance(&changed_url, &provenance).is_err());

        let mut changed_root = index;
        changed_root.root.fingerprint = root_fingerprint(b"different-root").to_string();
        assert!(validate_existing_index_provenance(&changed_root, &provenance).is_err());
    }
}
