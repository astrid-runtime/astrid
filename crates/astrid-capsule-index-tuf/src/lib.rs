//! The verified, static read plane for an Astrid Capsule Index.
//!
//! This crate deliberately delegates TUF parsing, signature verification, consistent snapshot
//! handling, root rotation, expiry checks, and metadata rollback checks to [`tough`].  It does not
//! implement a second signature format.  The Astrid-specific wrapper adds the policy that TUF
//! cannot know about: a pinned Index-root fingerprint, an atomic high-water state record, bounded
//! artifact reads, and the sparse content-addressed object naming convention used by Pages.
//!
//! A transport is supplied by the caller.  The production client can use a network transport in a
//! higher-level crate, while tests and air-gapped deployments can use [`MemoryTransport`] or
//! [`tough::FilesystemTransport`].  No HTTP client is enabled in this crate, so verification never
//! silently opens a network connection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use astrid_capsule_index::{Digest, DigestAlgorithm, IndexIdentity, TrustRootFingerprint};
use bytes::Bytes;
use fs2::FileExt;
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tough::error::Error as ToughError;
use tough::schema::Role;
use tough::{ExpirationEnforcement, IntoVec, Limits as ToughLimits, TargetName};
use url::Url;

/// The current sparse object layout emitted by the Index Pages generator.
pub const SPARSE_OBJECT_ROOT: &str = "objects";
/// The SHA-256 algorithm name used by TUF target metadata hashes.
pub const SHA256_ALGORITHM: &str = "sha256";

/// Compute the protocol's algorithm-tagged SHA-256 fingerprint over exact root bytes.
///
/// The returned [`TrustRootFingerprint`] is shared with Capsule Index source configuration,
/// protocol locks, and publication identity. Bytes are hashed as supplied; no JSON parsing or
/// re-encoding occurs first.
///
/// # Errors
///
/// Returns [`Error::Protocol`] only if the protocol digest constructor rejects the fixed-size
/// SHA-256 output (which indicates a dependency or implementation invariant failure).
pub fn root_fingerprint_from_bytes(root: &[u8]) -> Result<TrustRootFingerprint, Error> {
    let digest = Digest::from_bytes(DigestAlgorithm::Sha256, Sha256::digest(root))?;
    Ok(TrustRootFingerprint::new(digest))
}

/// Metadata and artifact limits applied by the wrapper and delegated to `tough`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Limits {
    /// Maximum downloaded root metadata bytes.
    pub max_root_bytes: u64,
    /// Maximum downloaded timestamp metadata bytes.
    pub max_timestamp_bytes: u64,
    /// Maximum downloaded snapshot metadata bytes.
    pub max_snapshot_bytes: u64,
    /// Maximum downloaded targets metadata bytes.
    pub max_targets_bytes: u64,
    /// Maximum root rotations followed in one load.
    pub max_root_updates: u64,
    /// Maximum target/object bytes returned by [`VerifiedIndex::read_target`].
    pub max_target_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        let tuf = ToughLimits::default();
        Self {
            max_root_bytes: tuf.max_root_size,
            max_timestamp_bytes: tuf.max_timestamp_size,
            max_snapshot_bytes: tuf.max_snapshot_size,
            max_targets_bytes: tuf.max_targets_size,
            max_root_updates: tuf.max_root_updates,
            // Capsule artifacts are bounded by policy at this interface.  Callers that need a
            // different bound must set it explicitly; there is no unbounded default.
            max_target_bytes: 64 * 1024 * 1024,
        }
    }
}

impl From<Limits> for ToughLimits {
    fn from(value: Limits) -> Self {
        Self {
            max_root_size: value.max_root_bytes,
            max_timestamp_size: value.max_timestamp_bytes,
            max_snapshot_size: value.max_snapshot_bytes,
            max_targets_size: value.max_targets_bytes,
            max_root_updates: value.max_root_updates,
        }
    }
}

/// Policy for a load explicitly marked as offline.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OfflinePolicy {
    /// Require every role to be unexpired.  This is the safe default.
    RejectExpired,
    /// Permit expired cached metadata.  This is an explicit availability trade-off and does not
    /// provide TUF freshness guarantees.
    AllowExpired,
}

/// Verification mode selected for a load.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VerificationMode {
    /// Verify freshness and expiry as an online update cycle.
    Online,
    /// Read from the supplied offline transport with an explicit expiry policy.
    Offline(OfflinePolicy),
}

/// Configuration for a single trusted Index source.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Stable Index identity, including its trust-root fingerprint. It is persisted with the
    /// high-water state and must not change when an application reuses that state path.
    pub index_identity: IndexIdentity,
    /// Exact root bytes shipped/pinned by the application.
    pub root_bytes: Vec<u8>,
    /// Metadata base URL (the caller decides whether this is HTTP, file, or another scheme).
    pub metadata_base_url: Url,
    /// Targets base URL.
    pub targets_base_url: Url,
    /// Atomic high-water state file.
    pub state_path: PathBuf,
    /// Tough's metadata datastore.  It is separate from `state_path`; callers should place both
    /// under a private application cache directory.
    pub datastore_path: PathBuf,
    /// Verification mode.
    pub mode: VerificationMode,
    /// Maximum metadata/object sizes.
    pub limits: Limits,
    /// Upper bound for the complete metadata update or target read operation.
    pub timeout: Duration,
}

impl TrustConfig {
    /// Construct configuration, checking that the supplied root fingerprint matches the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RootFingerprintMismatch`] when the exact bytes do not hash to the
    /// identity's `trust_root`.
    pub fn new(
        index_identity: IndexIdentity,
        root_bytes: impl AsRef<[u8]>,
        metadata_base_url: Url,
        targets_base_url: Url,
        state_path: impl Into<PathBuf>,
        datastore_path: impl Into<PathBuf>,
    ) -> Result<Self, Error> {
        let root_bytes = root_bytes.as_ref().to_vec();
        let actual = root_fingerprint_from_bytes(&root_bytes)?;
        if actual != index_identity.trust_root {
            return Err(Error::RootFingerprintMismatch {
                expected: index_identity.trust_root.clone(),
                actual,
            });
        }
        Ok(Self {
            index_identity,
            root_bytes,
            metadata_base_url,
            targets_base_url,
            state_path: state_path.into(),
            datastore_path: datastore_path.into(),
            mode: VerificationMode::Online,
            limits: Limits::default(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Set online/offline verification mode.
    #[must_use]
    pub fn mode(mut self, mode: VerificationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set metadata/object limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the complete-load/target-read timeout. A zero timeout is rejected when loading.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Persisted metadata versions and source identity.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustedState {
    /// Stable Index identity, including the initially pinned trust root (stable across root
    /// rotation).
    pub index_identity: IndexIdentity,
    /// Highest accepted root role version.
    pub root_version: u64,
    /// Canonical digest of the accepted root signed payload.
    pub root_digest: String,
    /// Highest accepted timestamp role version.
    pub timestamp_version: u64,
    /// Canonical digest of the accepted timestamp signed payload.
    pub timestamp_digest: String,
    /// Highest accepted snapshot role version.
    pub snapshot_version: u64,
    /// Canonical digest of the accepted snapshot signed payload.
    pub snapshot_digest: String,
    /// Highest accepted top-level targets role version.
    pub targets_version: u64,
    /// Canonical digest of the accepted top-level targets signed payload.
    pub targets_digest: String,
}

/// A verified TUF repository and its immutable generation.
#[derive(Debug)]
pub struct VerifiedIndex {
    repository: tough::Repository,
    state: TrustedState,
    metadata_bytes: HashMap<String, Vec<u8>>,
    /// Bootstrap root followed by every consecutive signed root fetched during this load.
    /// Keeping the chain (rather than only the final root) lets callers construct a complete,
    /// authenticated offline witness for multi-hop rotations.
    root_chain: Vec<(u64, Vec<u8>)>,
    limits: Limits,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct TransportObservation {
    url: String,
    kind: tough::TransportErrorKind,
    detail: String,
}

#[derive(Debug, Clone, Copy)]
enum BoundExceededKind {
    /// A top-level or delegated metadata stream exceeded its role bound.
    Metadata(&'static str),
    /// A target/object stream exceeded the target bound.
    Target,
}

#[derive(Debug)]
struct BoundExceeded {
    kind: BoundExceededKind,
    size: u64,
    limit: u64,
}

impl std::fmt::Display for BoundExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            BoundExceededKind::Metadata(role) => write!(
                formatter,
                "{role} metadata exceeded wrapper limit {} at {} bytes",
                self.limit, self.size
            ),
            BoundExceededKind::Target => write!(
                formatter,
                "target exceeded wrapper limit {} at {} bytes",
                self.limit, self.size
            ),
        }
    }
}

impl std::error::Error for BoundExceeded {}

fn bounded_stream(
    inner: tough::TransportStream,
    url: Url,
    limit: u64,
    kind: BoundExceededKind,
) -> tough::TransportStream {
    Box::pin(stream::unfold(
        (inner, 0u64),
        move |(mut inner, mut size)| {
            let kind = kind;
            let url = url.clone();
            async move {
                match inner.next().await {
                    Some(Ok(bytes)) => {
                        size = size.saturating_add(bytes.len() as u64);
                        if size > limit {
                            let error = tough::TransportError::new_with_cause(
                                tough::TransportErrorKind::Other,
                                url,
                                BoundExceeded { kind, size, limit },
                            );
                            Some((Err(error), (inner, size)))
                        } else {
                            Some((Ok(bytes), (inner, size)))
                        }
                    },
                    Some(Err(error)) => Some((Err(error), (inner, size))),
                    None => None,
                }
            }
        },
    ))
}

#[derive(Debug, Clone)]
struct ObservingTransport<T> {
    inner: T,
    failures: Arc<std::sync::Mutex<Vec<TransportObservation>>>,
    metadata: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    metadata_base_url: Url,
    targets_base_url: Url,
    limits: Limits,
}

type FailureObservations = Arc<std::sync::Mutex<Vec<TransportObservation>>>;
type MetadataObservations = Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>;

#[derive(Debug)]
struct StateLock {
    file: std::fs::File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn state_lock_path(path: &Path) -> PathBuf {
    let mut lock = path.to_owned();
    let suffix = lock
        .extension()
        .and_then(|extension| extension.to_str())
        .map_or_else(
            || "lock".to_owned(),
            |extension| format!("{extension}.lock"),
        );
    lock.set_extension(suffix);
    lock
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn acquire_state_lock(path: &Path, timeout: Duration) -> Result<StateLock, Error> {
    let parent = parent_dir(path);
    std::fs::create_dir_all(parent).map_err(|source| Error::Io {
        operation: "create trusted-state lock directory",
        path: parent.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| Error::Io {
                operation: "restrict trusted-state lock directory",
                path: parent.to_owned(),
                source,
            },
        )?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|source| Error::Io {
                operation: "open trusted-state lock",
                path: path.to_owned(),
                source,
            })?;
        let start = std::time::Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(StateLock { file }),
                Err(source)
                    if source.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < timeout =>
                {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    std::thread::sleep(Duration::from_millis(10).min(remaining));
                },
                Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(Error::Timeout {
                        operation: "trusted state lock",
                        timeout,
                    });
                },
                Err(source) => {
                    return Err(Error::Io {
                        operation: "lock trusted state",
                        path: path.to_owned(),
                        source,
                    });
                },
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = timeout;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| Error::Io {
                operation: "open trusted-state lock",
                path: path.to_owned(),
                source,
            })?;
        file.lock_exclusive().map_err(|source| Error::Io {
            operation: "lock trusted state",
            path: path.to_owned(),
            source,
        })?;
        Ok(StateLock { file })
    }
}

impl<T> ObservingTransport<T> {
    fn new(
        inner: T,
        metadata_base_url: Url,
        targets_base_url: Url,
        limits: Limits,
    ) -> (Self, FailureObservations, MetadataObservations) {
        let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
        let metadata = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let metadata_base_url = normalize_base_url(metadata_base_url);
        let targets_base_url = normalize_base_url(targets_base_url);
        (
            Self {
                inner,
                failures: failures.clone(),
                metadata: metadata.clone(),
                metadata_base_url,
                targets_base_url,
                limits,
            },
            failures,
            metadata,
        )
    }
}

fn normalize_base_url(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

fn bound_for_url(
    url: &Url,
    metadata_base_url: &Url,
    targets_base_url: &Url,
    limits: Limits,
) -> Option<(u64, BoundExceededKind)> {
    if let Some(metadata_relative) = url.as_str().strip_prefix(metadata_base_url.as_str()) {
        let filename = metadata_relative.rsplit('/').next().unwrap_or_default();
        if let Some((limit, kind)) = metadata_bound(filename, limits) {
            return Some((limit, kind));
        }
        if url.as_str().starts_with(targets_base_url.as_str()) {
            return Some((limits.max_target_bytes, BoundExceededKind::Target));
        }
        return Some((
            limits.max_targets_bytes,
            BoundExceededKind::Metadata("metadata"),
        ));
    }
    url.as_str()
        .starts_with(targets_base_url.as_str())
        .then_some((limits.max_target_bytes, BoundExceededKind::Target))
}

fn metadata_bound(filename: &str, limits: Limits) -> Option<(u64, BoundExceededKind)> {
    if filename == "timestamp.json" {
        return Some((
            limits.max_timestamp_bytes,
            BoundExceededKind::Metadata("timestamp"),
        ));
    }
    if filename == "snapshot.json" {
        return Some((
            limits.max_snapshot_bytes,
            BoundExceededKind::Metadata("snapshot"),
        ));
    }
    if filename == "targets.json" {
        return Some((
            limits.max_targets_bytes,
            BoundExceededKind::Metadata("targets"),
        ));
    }
    if filename == "root.json" {
        return Some((limits.max_root_bytes, BoundExceededKind::Metadata("root")));
    }
    let (version, suffix) = filename.split_once('.')?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match suffix {
        "snapshot.json" => Some((
            limits.max_snapshot_bytes,
            BoundExceededKind::Metadata("snapshot"),
        )),
        "targets.json" => Some((
            limits.max_targets_bytes,
            BoundExceededKind::Metadata("targets"),
        )),
        "root.json" => Some((limits.max_root_bytes, BoundExceededKind::Metadata("root"))),
        _ => None,
    }
}

#[tough::async_trait]
impl<T> tough::Transport for ObservingTransport<T>
where
    T: tough::Transport + Clone + Send + Sync + 'static,
{
    async fn fetch(&self, url: Url) -> Result<tough::TransportStream, tough::TransportError> {
        match self.inner.fetch(url.clone()).await {
            Ok(stream) => {
                let stream = match bound_for_url(
                    &url,
                    &self.metadata_base_url,
                    &self.targets_base_url,
                    self.limits,
                ) {
                    Some((limit, kind)) => bounded_stream(stream, url.clone(), limit, kind),
                    None => stream,
                };
                let bytes = stream.into_vec().await?;
                let metadata_relative = url
                    .as_str()
                    .strip_prefix(self.metadata_base_url.as_str())
                    .unwrap_or_default();
                let filename = metadata_relative.rsplit('/').next().unwrap_or_default();
                if (filename == "timestamp.json" || metadata_bound(filename, self.limits).is_some())
                    && let Ok(mut metadata) = self.metadata.lock()
                {
                    // Keep every versioned root fetched by `tough`.  A rotated root is only
                    // trusted through the consecutive chain, and offline callers need each
                    // intermediate role to replay that chain. `RepositoryLoader` bounds the
                    // number of updates while `bounded_stream` bounds every root body.
                    metadata.insert(url.to_string(), bytes.clone());
                }
                Ok(Box::pin(stream::iter([Ok(Bytes::from(bytes))])))
            },
            Err(error) => {
                if error.kind() != tough::TransportErrorKind::FileNotFound
                    && let Ok(mut failures) = self.failures.lock()
                {
                    failures.push(TransportObservation {
                        url: url.to_string(),
                        kind: error.kind(),
                        detail: error.to_string(),
                    });
                }
                Err(error)
            },
        }
    }
}

impl VerifiedIndex {
    /// Return the state committed after this generation was verified.
    #[must_use]
    pub fn state(&self) -> &TrustedState {
        &self.state
    }

    /// Return the verified repository root role (including a rotated root, if any).
    #[must_use]
    pub fn root(&self) -> &tough::schema::Signed<tough::schema::Root> {
        self.repository.root()
    }

    /// Return the exact bytes fetched for the final root role, or the shipped bootstrap root when
    /// no root rotation was needed.
    #[must_use]
    pub fn root_bytes(&self) -> &[u8] {
        self.root_chain
            .last()
            .map_or(&[] as &[u8], |(_, bytes)| bytes.as_slice())
    }

    /// Return the complete bootstrap-to-final signed root chain for this generation.
    ///
    /// The first item is the exact shipped bootstrap root. Subsequent items are the exact bytes
    /// fetched at each consecutive versioned root URL. The chain is bounded by
    /// [`Limits::max_root_updates`] and was already signature-verified by `tough`.
    #[must_use]
    pub fn root_chain_bytes(&self) -> Vec<(u64, &[u8])> {
        self.root_chain
            .iter()
            .map(|(version, bytes)| (*version, bytes.as_slice()))
            .collect()
    }

    /// Return the exact timestamp metadata bytes fetched for this generation.
    #[must_use]
    pub fn timestamp_bytes(&self) -> Option<&[u8]> {
        self.metadata_bytes
            .iter()
            .find(|(path, _)| path.ends_with("/timestamp.json") || path.ends_with("timestamp.json"))
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Return the exact snapshot metadata bytes fetched for this generation.
    #[must_use]
    pub fn snapshot_bytes(&self) -> Option<&[u8]> {
        self.metadata_bytes
            .iter()
            .find(|(path, _)| path.ends_with(".snapshot.json") || path.ends_with("/snapshot.json"))
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Return the exact top-level targets metadata bytes fetched for this generation.
    #[must_use]
    pub fn targets_bytes(&self) -> Option<&[u8]> {
        self.metadata_bytes
            .iter()
            .find(|(path, _)| path.ends_with(".targets.json") || path.ends_with("/targets.json"))
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Return the verified timestamp role.
    #[must_use]
    pub fn timestamp(&self) -> &tough::schema::Signed<tough::schema::Timestamp> {
        self.repository.timestamp()
    }

    /// Return the verified snapshot role.
    #[must_use]
    pub fn snapshot(&self) -> &tough::schema::Signed<tough::schema::Snapshot> {
        self.repository.snapshot()
    }

    /// Return the verified top-level targets role.
    #[must_use]
    pub fn targets(&self) -> &tough::schema::Signed<tough::schema::Targets> {
        self.repository.targets()
    }

    /// Look up a target by its exact Index target path and return verified bytes.
    ///
    /// `tough` verifies the role signatures, consistent-snapshot metadata references, and the
    /// target SHA-256 while streaming.  The wrapper additionally checks the declared target length
    /// and a second digest so a short stream cannot be accepted as a valid artifact.
    ///
    /// # Errors
    ///
    /// Returns a structured error for a missing target, timeout, transport/verification failure,
    /// size/length mismatch, or digest mismatch.
    pub async fn read_target(&self, target_path: impl AsRef<str>) -> Result<Vec<u8>, Error> {
        let target_path = target_path.as_ref().to_owned();
        let target_name =
            TargetName::new(target_path.clone()).map_err(|_| Error::MissingTarget {
                target: target_path.clone(),
            })?;
        let target = self
            .repository
            .targets()
            .signed
            .find_target(&target_name, false)
            .map_err(|_| Error::MissingTarget {
                target: target_path.clone(),
            })?;
        let expected_length = target.length;
        let expected_digest = target.hashes.sha256.as_ref().to_vec();
        if expected_length > self.limits.max_target_bytes {
            return Err(Error::TargetTooLarge {
                target: target_path,
                size: expected_length,
                limit: self.limits.max_target_bytes,
            });
        }

        let read = async {
            let stream = self
                .repository
                .read_target(&target_name)
                .await
                .map_err(classify_tough)?
                .ok_or_else(|| Error::MissingTarget {
                    target: target_name.raw().to_owned(),
                })?;
            stream.into_vec().await.map_err(classify_tough)
        };
        let bytes = tokio::time::timeout(self.timeout, read)
            .await
            .map_err(|_| Error::Timeout {
                operation: "target read",
                timeout: self.timeout,
            })??;
        if bytes.len() as u64 != expected_length {
            return Err(Error::LengthMismatch {
                target: target_name.raw().to_owned(),
                expected: expected_length,
                actual: bytes.len() as u64,
            });
        }
        let actual_digest = Sha256::digest(&bytes);
        if actual_digest.as_slice() != expected_digest.as_slice() {
            return Err(Error::DigestMismatch {
                target: target_name.raw().to_owned(),
                expected: hex::encode(expected_digest),
                actual: hex::encode(actual_digest),
            });
        }
        Ok(bytes)
    }

    /// Resolve and read a sparse object at `/objects/<algorithm>/<prefix>/<digest>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedDigestAlgorithm`] or [`Error::InvalidDigest`] for an invalid
    /// object coordinate, or the same read errors as [`Self::read_target`].
    pub async fn read_sparse_object(
        &self,
        algorithm: impl AsRef<str>,
        digest: impl AsRef<str>,
    ) -> Result<Vec<u8>, Error> {
        let target = sparse_object_path(algorithm.as_ref(), digest.as_ref())?;
        self.read_target(target).await
    }
}

/// Construct a sparse, content-addressed target path without consulting mutable repository state.
///
/// # Errors
///
/// The algorithm is parsed using the protocol's [`DigestAlgorithm`] set, so sparse objects may
/// use SHA-256, SHA-384, SHA-512, or BLAKE3. TUF's own target hash remains SHA-256; the algorithm
/// here identifies the content-addressed Index object path.
///
/// Returns [`Error::UnsupportedDigestAlgorithm`] for an unknown algorithm and
/// [`Error::InvalidDigest`] for a malformed digest.
pub fn sparse_object_path(algorithm: &str, digest: &str) -> Result<String, Error> {
    DigestAlgorithm::parse(algorithm).map_err(|_| Error::UnsupportedDigestAlgorithm {
        algorithm: algorithm.to_owned(),
    })?;
    let parsed =
        Digest::parse(&format!("{algorithm}:{digest}")).map_err(|_| Error::InvalidDigest {
            digest: digest.to_owned(),
        })?;
    let digest = parsed.hex();
    Ok(format!(
        "{SPARSE_OBJECT_ROOT}/{}/{}/{}.json",
        parsed.algorithm().as_str(),
        &digest[..2],
        digest
    ))
}

/// Construct a sparse object path from an already validated protocol digest.
#[must_use]
pub fn sparse_object_path_from_digest(digest: &Digest) -> String {
    let hex = digest.hex();
    format!(
        "{SPARSE_OBJECT_ROOT}/{}/{}/{}.json",
        digest.algorithm().as_str(),
        &hex[..2],
        hex
    )
}

/// Load and verify an Index using a caller-supplied transport.
///
/// # Errors
///
/// Returns a structured error when the bootstrap root, TUF metadata, transport, persistence,
/// expiry, rollback, or configured bounds fail validation.
#[allow(clippy::too_many_lines)]
pub async fn load<T>(config: TrustConfig, transport: T) -> Result<VerifiedIndex, Error>
where
    T: tough::Transport + Clone + Send + Sync + 'static,
{
    let actual_root_fingerprint = root_fingerprint_from_bytes(&config.root_bytes)?;
    if actual_root_fingerprint != config.index_identity.trust_root {
        return Err(Error::RootFingerprintMismatch {
            expected: config.index_identity.trust_root.clone(),
            actual: actual_root_fingerprint,
        });
    }
    if config.timeout.is_zero() {
        return Err(Error::InvalidTimeout);
    }
    if config.root_bytes.len() as u64 > config.limits.max_root_bytes {
        return Err(Error::MetadataTooLarge {
            role: "root",
            size: config.root_bytes.len() as u64,
            limit: config.limits.max_root_bytes,
        });
    }

    let lock_path = state_lock_path(&config.state_path);
    let lock_timeout = config.timeout;
    let _state_lock = tokio::time::timeout(
        config.timeout,
        tokio::task::spawn_blocking(move || acquire_state_lock(&lock_path, lock_timeout)),
    )
    .await
    .map_err(|_| Error::Timeout {
        operation: "trusted state lock",
        timeout: config.timeout,
    })?
    .map_err(|source| Error::Verification {
        detail: format!("trusted state lock task failed: {source}"),
    })??;
    let prior = read_state(&config.state_path).await?;
    if let Some(previous) = &prior
        && previous.index_identity != config.index_identity
    {
        return Err(Error::StateIdentityMismatch {
            expected: config.index_identity.clone(),
            actual: previous.index_identity.clone(),
        });
    }

    tokio::fs::create_dir_all(&config.datastore_path)
        .await
        .map_err(|source| Error::Io {
            operation: "create TUF datastore",
            path: config.datastore_path.clone(),
            source,
        })?;

    let enforcement = match config.mode {
        VerificationMode::Online | VerificationMode::Offline(OfflinePolicy::RejectExpired) => {
            ExpirationEnforcement::Safe
        },
        VerificationMode::Offline(OfflinePolicy::AllowExpired) => ExpirationEnforcement::Unsafe,
    };
    let (transport, observations, metadata) = ObservingTransport::new(
        transport,
        config.metadata_base_url.clone(),
        config.targets_base_url.clone(),
        config.limits,
    );
    let loader = tough::RepositoryLoader::new(
        &config.root_bytes,
        config.metadata_base_url.clone(),
        config.targets_base_url.clone(),
    )
    .transport(transport)
    .limits(config.limits.into())
    .datastore(config.datastore_path.clone())
    .expiration_enforcement(enforcement);
    let repository = tokio::time::timeout(config.timeout, loader.load())
        .await
        .map_err(|_| Error::Timeout {
            operation: "metadata load",
            timeout: config.timeout,
        })?
        .map_err(classify_tough)?;
    let mut metadata_bytes = metadata
        .lock()
        .map_or_else(|_| HashMap::new(), |metadata| metadata.clone());
    metadata_bytes.insert("__bootstrap_root".to_owned(), config.root_bytes.clone());
    // Astrid's Pages layout and target resolution rely on versioned metadata and target names.
    // A repository that opts out of TUF consistent snapshots is therefore not a valid Index
    // source, even though `tough` can technically load it.
    if !repository.root().signed.consistent_snapshot {
        return Err(Error::Verification {
            detail: "Index root must enable consistent snapshots".to_owned(),
        });
    }
    let final_root_name = format!("{}.root.json", repository.root().signed.version);
    metadata_bytes.retain(|path, _| {
        path == "__bootstrap_root"
            || path.ends_with(&final_root_name)
            || versioned_root_from_path(path).is_some()
            || path.ends_with("/timestamp.json")
            || path.ends_with(".snapshot.json")
            || path.ends_with(".targets.json")
    });
    if let Ok(mut failures) = observations.lock()
        && let Some(failure) = failures.pop()
    {
        return Err(Error::Transport {
            url: failure.url,
            kind: failure.kind,
            detail: failure.detail,
        });
    }

    let root_chain = collect_root_chain(&metadata_bytes, repository.root().signed.version.get())?;
    // Root bytes now live in the bounded chain owned by `VerifiedIndex`; avoid retaining a
    // second copy in the generic metadata map used for the offline witness roles.
    metadata_bytes.retain(|path, _| {
        path.ends_with("/timestamp.json")
            || path.ends_with(".snapshot.json")
            || path.ends_with(".targets.json")
    });

    let state = TrustedState {
        index_identity: config.index_identity.clone(),
        root_version: repository.root().signed.version.get(),
        root_digest: role_digest(&repository.root().signed)?,
        timestamp_version: repository.timestamp().signed.version.get(),
        timestamp_digest: role_digest(&repository.timestamp().signed)?,
        snapshot_version: repository.snapshot().signed.version.get(),
        snapshot_digest: role_digest(&repository.snapshot().signed)?,
        targets_version: repository.targets().signed.version.get(),
        targets_digest: role_digest(&repository.targets().signed)?,
    };
    if let Some(previous) = &prior {
        check_monotonic(previous, &state)?;
    }
    // Only after all four roles have been verified and high-water checks have passed do we replace
    // the state file.  `persist_state` uses write+sync+rename, so an interrupted write leaves the
    // previous trusted state intact.
    persist_state(&config.state_path, &state).await?;

    Ok(VerifiedIndex {
        repository,
        state,
        metadata_bytes,
        root_chain,
        limits: config.limits,
        timeout: config.timeout,
    })
}

fn versioned_root_from_path(path: &str) -> Option<u64> {
    let filename = path.rsplit('/').next().unwrap_or_default();
    let version = filename.strip_suffix(".root.json")?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    version.parse().ok()
}

fn collect_root_chain(
    metadata: &HashMap<String, Vec<u8>>,
    final_version: u64,
) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    let bootstrap = metadata
        .get("__bootstrap_root")
        .ok_or_else(|| Error::Verification {
            detail: "bootstrap root bytes were not retained".to_owned(),
        })?;
    let bootstrap_root = serde_json::from_slice::<tough::schema::Signed<tough::schema::Root>>(
        bootstrap,
    )
    .map_err(|source| Error::Verification {
        detail: format!("bootstrap root bytes are invalid: {source}"),
    })?;
    let mut roots = vec![(bootstrap_root.signed.version.get(), bootstrap.clone())];
    let mut fetched = metadata
        .iter()
        .filter_map(|(path, bytes)| versioned_root_from_path(path).map(|version| (version, bytes)))
        .filter(|(version, _)| *version <= final_version)
        .map(|(version, bytes)| (version, bytes.clone()))
        .collect::<Vec<_>>();
    fetched.sort_by_key(|(version, _)| *version);
    for (version, bytes) in fetched {
        if let Some((_, existing)) = roots.iter().find(|(seen, _)| *seen == version) {
            if existing != &bytes {
                return Err(Error::Verification {
                    detail: format!("conflicting root bytes for version {version}"),
                });
            }
            continue;
        }
        roots.push((version, bytes));
    }
    roots.sort_by_key(|(version, _)| *version);
    for pair in roots.windows(2) {
        let expected = pair[0].0.saturating_add(1);
        if pair[1].0 != expected {
            return Err(Error::Verification {
                detail: format!(
                    "root rotation chain skips version {} before {}",
                    expected, pair[1].0
                ),
            });
        }
    }
    let observed_final = roots.last().map_or(0, |(version, _)| *version);
    if observed_final != final_version {
        return Err(Error::Verification {
            detail: format!(
                "root rotation chain ends at {observed_final}, repository accepted {final_version}"
            ),
        });
    }
    Ok(roots)
}

fn check_monotonic(previous: &TrustedState, current: &TrustedState) -> Result<(), Error> {
    for (role, old, new, old_digest, new_digest) in [
        (
            "root",
            previous.root_version,
            current.root_version,
            &previous.root_digest,
            &current.root_digest,
        ),
        (
            "timestamp",
            previous.timestamp_version,
            current.timestamp_version,
            &previous.timestamp_digest,
            &current.timestamp_digest,
        ),
        (
            "snapshot",
            previous.snapshot_version,
            current.snapshot_version,
            &previous.snapshot_digest,
            &current.snapshot_digest,
        ),
        (
            "targets",
            previous.targets_version,
            current.targets_version,
            &previous.targets_digest,
            &current.targets_digest,
        ),
    ] {
        if new < old {
            return Err(Error::Rollback {
                role: role.to_owned(),
                trusted: old,
                observed: new,
            });
        }
        if new == old && old_digest != new_digest {
            return Err(Error::Equivocation {
                role: role.to_owned(),
                version: new,
            });
        }
    }
    Ok(())
}

fn role_digest<R: Role>(role: &R) -> Result<String, Error> {
    let canonical = role
        .canonical_form()
        .map_err(|source| Error::Verification {
            detail: source.to_string(),
        })?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

async fn read_state(path: &Path) -> Result<Option<TrustedState>, Error> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|source| Error::StateCorrupt {
                    path: path.to_owned(),
                    source,
                })
        },
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io {
            operation: "read trusted state",
            path: path.to_owned(),
            source,
        }),
    }
}

async fn persist_state(path: &Path, state: &TrustedState) -> Result<(), Error> {
    let parent = parent_dir(path);
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|source| Error::Io {
            operation: "create trusted-state directory",
            path: parent.to_owned(),
            source,
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| Error::Io {
                operation: "restrict trusted-state directory",
                path: parent.to_owned(),
                source,
            },
        )?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|source| Error::StateSerialize {
        path: path.to_owned(),
        source,
    })?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        uuid::Uuid::new_v4()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let write_result = async {
        let mut file = options.open(&temp).await?;
        file.write_all(&bytes).await?;
        // Sync while the temporary file is still private and unreferenced. This also ensures a
        // crash cannot leave a partially written state file if the rename below has completed.
        file.sync_all().await
    }
    .await;
    if let Err(source) = write_result {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(Error::Io {
            operation: "write trusted-state temporary file",
            path: temp,
            source,
        });
    }
    // A crash can leave an unreferenced temporary file, but cannot expose a partially written
    // trusted state at `path`.
    if let Err(source) = tokio::fs::rename(&temp, path).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(Error::Io {
            operation: "commit trusted state",
            path: path.to_owned(),
            source,
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| Error::Io {
                operation: "restrict trusted-state file",
                path: path.to_owned(),
                source,
            },
        )?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| Error::Io {
                operation: "sync trusted-state directory",
                path: parent.to_owned(),
                source,
            })?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "Exhaustive mapping preserves tough failure categories"
)]
fn classify_tough(error: ToughError) -> Error {
    match error {
        ToughError::ExpiredMetadata { role, .. } => Error::Expired {
            role: role.to_string(),
        },
        ToughError::OlderMetadata {
            role,
            current_version,
            new_version,
            ..
        } => Error::Rollback {
            role: role.to_string(),
            trusted: current_version,
            observed: new_version,
        },
        ToughError::OlderSnapshotInTimestamp {
            snapshot_old,
            snapshot_new,
            ..
        } => Error::Rollback {
            role: "snapshot".to_owned(),
            trusted: snapshot_old,
            observed: snapshot_new,
        },
        ToughError::SnapshotRoleRollback {
            role,
            old_role_version,
            new_role_version,
            ..
        } => Error::Rollback {
            role,
            trusted: old_role_version,
            observed: new_role_version,
        },
        ToughError::HashMismatch {
            context,
            calculated,
            expected,
            ..
        } => Error::DigestMismatch {
            target: context,
            expected,
            actual: calculated,
        },
        ToughError::MaxSizeExceeded {
            max_size,
            specifier,
            ..
        } => Error::MetadataTooLarge {
            role: specifier,
            size: max_size.saturating_add(1),
            limit: max_size,
        },
        ToughError::CacheTargetMissing { target_name, .. } => Error::MissingTarget {
            target: target_name.raw().to_owned(),
        },
        ToughError::Transport { url, source, .. } => {
            // Target streams and metadata size adapters surface their verification errors as a
            // `TransportError` whose source is the original tough error. Preserve that structured
            // classification instead of flattening a hash/size failure into generic transport.
            if let Some(bound) =
                StdError::source(&source).and_then(|cause| cause.downcast_ref::<BoundExceeded>())
            {
                return match bound.kind {
                    BoundExceededKind::Metadata(role) => Error::MetadataTooLarge {
                        role,
                        size: bound.size,
                        limit: bound.limit,
                    },
                    BoundExceededKind::Target => Error::TargetTooLarge {
                        target: url.to_string(),
                        size: bound.size,
                        limit: bound.limit,
                    },
                };
            }
            if let Some(inner) =
                StdError::source(&source).and_then(|cause| cause.downcast_ref::<ToughError>())
            {
                match inner {
                    ToughError::HashMismatch {
                        context,
                        calculated,
                        expected,
                        ..
                    } => {
                        return Error::DigestMismatch {
                            target: context.clone(),
                            expected: expected.clone(),
                            actual: calculated.clone(),
                        };
                    },
                    ToughError::MaxSizeExceeded {
                        max_size,
                        specifier,
                        ..
                    } => {
                        return Error::MetadataTooLarge {
                            role: specifier,
                            size: max_size.saturating_add(1),
                            limit: *max_size,
                        };
                    },
                    _ => {},
                }
            }
            Error::Transport {
                url: url.to_string(),
                kind: source.kind(),
                detail: source.to_string(),
            }
        },
        other => Error::Verification {
            detail: other.to_string(),
        },
    }
}

/// Structured verification failures exposed to callers.
#[derive(Debug, Error)]
pub enum Error {
    /// The bootstrap root bytes do not match the pinned Index fingerprint.
    #[error("Index root fingerprint mismatch: expected {expected}, got {actual}")]
    RootFingerprintMismatch {
        /// Fingerprint configured by the caller.
        expected: TrustRootFingerprint,
        /// Fingerprint calculated from the supplied bytes.
        actual: TrustRootFingerprint,
    },
    /// Existing trusted state belongs to another Index/root.
    #[error("trusted state belongs to Index {actual:?}, expected {expected:?}")]
    StateIdentityMismatch {
        /// Index identity configured by the caller.
        expected: IndexIdentity,
        /// Index identity persisted in the state file.
        actual: IndexIdentity,
    },
    /// State JSON could not be decoded; fail closed rather than discard it.
    #[error("trusted state at {path} is corrupt: {source}")]
    StateCorrupt {
        /// State file path.
        path: PathBuf,
        /// JSON decoding error.
        #[source]
        source: serde_json::Error,
    },
    /// State serialization failed.
    #[error("could not serialize trusted state at {path}: {source}")]
    StateSerialize {
        /// State file path.
        path: PathBuf,
        /// JSON encoding error.
        #[source]
        source: serde_json::Error,
    },
    /// A metadata role was expired or frozen.
    #[error("{role} metadata is expired")]
    Expired {
        /// Expired role name.
        role: String,
    },
    /// A role version decreased relative to the persisted high-water mark.
    #[error("{role} metadata rollback: trusted version {trusted}, observed {observed}")]
    Rollback {
        /// Role name.
        role: String,
        /// Highest previously trusted version.
        trusted: u64,
        /// Version in the candidate generation.
        observed: u64,
    },
    /// A role reused a version number for different signed content.
    #[error("{role} metadata equivocation at version {version}")]
    Equivocation {
        /// Role name.
        role: String,
        /// Reused version.
        version: u64,
    },
    /// The requested target is absent from verified targets metadata.
    #[error("target {target:?} is missing")]
    MissingTarget {
        /// Requested target path.
        target: String,
    },
    /// A target exceeded the caller's explicit byte bound.
    #[error("target {target:?} is {size} bytes, exceeding limit {limit}")]
    TargetTooLarge {
        /// Target path.
        target: String,
        /// Declared target size.
        size: u64,
        /// Configured target-size bound.
        limit: u64,
    },
    /// A metadata stream exceeded its configured bound.
    #[error("{role} metadata is {size} bytes, exceeding limit {limit}")]
    MetadataTooLarge {
        /// Role or tough limit specifier.
        role: &'static str,
        /// Observed size (or a lower bound when tough stopped a stream).
        size: u64,
        /// Configured bound.
        limit: u64,
    },
    /// Declared target length did not match downloaded bytes.
    #[error("target {target:?} length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Target path.
        target: String,
        /// Declared length.
        expected: u64,
        /// Downloaded length.
        actual: u64,
    },
    /// Declared target digest did not match downloaded bytes.
    #[error("target {target:?} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Target path or metadata URL.
        target: String,
        /// Declared digest.
        expected: String,
        /// Calculated digest.
        actual: String,
    },
    /// A transport could not obtain metadata or target bytes.
    #[error("transport {kind:?} fetching {url}: {detail}")]
    Transport {
        /// URL being fetched.
        url: String,
        /// Vetted transport classification.
        kind: tough::TransportErrorKind,
        /// Transport detail.
        detail: String,
    },
    /// A filesystem or state operation failed.
    #[error("{operation} at {path}: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A verification/parser failure from the vetted TUF implementation.
    #[error("TUF verification failed: {detail}")]
    Verification {
        /// Tough's structured error rendered for this wrapper boundary.
        detail: String,
    },
    /// An unsupported sparse-object digest algorithm.
    #[error("unsupported digest algorithm {algorithm:?}")]
    UnsupportedDigestAlgorithm {
        /// Requested algorithm.
        algorithm: String,
    },
    /// A sparse-object digest was not exactly a 32-byte hexadecimal SHA-256 value.
    #[error("invalid object digest {digest:?}")]
    InvalidDigest {
        /// Invalid digest input.
        digest: String,
    },
    /// A load or target operation was configured with no time budget.
    #[error("timeout must be greater than zero")]
    InvalidTimeout,
    /// A protocol-domain value (for example an algorithm-tagged digest) was invalid.
    #[error("invalid Capsule Index value: {0}")]
    Protocol(#[from] astrid_capsule_index::IndexError),
    /// A metadata or target operation exceeded its explicit deadline.
    #[error("{operation} exceeded timeout of {timeout:?}")]
    Timeout {
        /// Operation that exceeded its deadline.
        operation: &'static str,
        /// Configured deadline.
        timeout: Duration,
    },
}

/// A deterministic in-memory transport for fixtures and offline callers.
#[derive(Debug, Clone, Default)]
pub struct MemoryTransport {
    files: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryTransport {
    /// Create an empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a fixture at an exact URL.
    pub fn insert(&self, url: &Url, bytes: impl Into<Vec<u8>>) {
        if let Ok(mut files) = self.files.write() {
            files.insert(url.to_string(), bytes.into());
        }
    }

    /// Insert a relative path below a base URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] when `path` cannot be joined to `base`.
    pub fn insert_path(
        &self,
        base: &Url,
        path: &str,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<(), Error> {
        let url = base.join(path).map_err(|source| Error::Verification {
            detail: format!("invalid fixture URL: {source}"),
        })?;
        self.insert(&url, bytes);
        Ok(())
    }
}

#[tough::async_trait]
impl tough::Transport for MemoryTransport {
    async fn fetch(&self, url: Url) -> Result<tough::TransportStream, tough::TransportError> {
        let bytes = self
            .files
            .read()
            .map_err(|_| tough::TransportError::new(tough::TransportErrorKind::Other, &url))?
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| {
                tough::TransportError::new(tough::TransportErrorKind::FileNotFound, &url)
            })?;
        let stream = stream::iter([Ok::<Bytes, tough::TransportError>(Bytes::from(bytes))]);
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod fixture {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use olpc_cjson::CanonicalFormatter;
    use serde_json::{Value, json};

    const EXPIRES: &str = "2999-01-01T00:00:00Z";

    #[derive(Debug)]
    pub(super) struct Fixture {
        pub(super) root: Vec<u8>,
        pub(super) identity: IndexIdentity,
        pub(super) base: Url,
        pub(super) transport: MemoryTransport,
        pub(super) target_path: String,
        pub(super) target_digest: String,
        pub(super) target_sha256: String,
    }

    fn canonical(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut bytes, CanonicalFormatter::new());
        value.serialize(&mut serializer).unwrap();
        bytes
    }

    fn key_object(key: &SigningKey) -> Value {
        json!({
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": { "public": hex::encode(key.verifying_key().to_bytes()) }
        })
    }

    fn key_id(key: &SigningKey) -> String {
        hex::encode(Sha256::digest(canonical(&key_object(key))))
    }

    fn signed(role: &Value, keys: &[SigningKey]) -> Vec<u8> {
        let message = canonical(role);
        let signatures = keys
            .iter()
            .map(|key| {
                json!({
                    "keyid": key_id(key),
                    "sig": hex::encode(key.sign(&message).to_bytes())
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({ "signed": role, "signatures": signatures })).unwrap()
    }

    fn roles(keys: &[SigningKey]) -> Value {
        let ids = keys.iter().map(key_id).collect::<Vec<_>>();
        json!({
            "root": { "keyids": ids, "threshold": 2 },
            "snapshot": { "keyids": ids, "threshold": 2 },
            "targets": { "keyids": ids, "threshold": 2 },
            "timestamp": { "keyids": ids, "threshold": 2 }
        })
    }

    fn root(keys: &[SigningKey], version: u64) -> Vec<u8> {
        let key_map = keys
            .iter()
            .map(|key| (key_id(key), key_object(key)))
            .collect::<serde_json::Map<_, _>>();
        signed(
            &json!({
                "_type": "root",
                "spec_version": "1.0.0",
                "consistent_snapshot": true,
                "version": version,
                "expires": EXPIRES,
                "keys": key_map,
                "roles": roles(keys)
            }),
            keys,
        )
    }

    fn fixture(
        index_id: &str,
        root_version: u64,
        timestamp_version: u64,
        snapshot_version: u64,
        targets_version: u64,
        expired: bool,
    ) -> Fixture {
        let seed_a = [index_id.as_bytes()[0].wrapping_add(1); 32];
        let seed_b = [index_id.as_bytes()[0].wrapping_add(2); 32];
        let keys = vec![
            SigningKey::from_bytes(&seed_a),
            SigningKey::from_bytes(&seed_b),
        ];
        // The shipped root remains the trust anchor during rotation.  `tough` then fetches each
        // consecutive versioned root (`2.root.json`, ...), so fixtures with a rotated root must
        // expose the complete chain rather than replacing the bootstrap bytes.
        let bootstrap_root = root(&keys, 1);
        let identity = IndexIdentity::new(
            index_id.parse().unwrap(),
            root_fingerprint_from_bytes(&bootstrap_root).unwrap(),
        );
        let base = Url::parse("memory://capsule-index/v1/").unwrap();
        let target_bytes = format!("{index_id}-capsule").into_bytes();
        let target_digest = Digest::blake3(&target_bytes).hex();
        let target_path = sparse_object_path_from_digest(&Digest::blake3(&target_bytes));
        let target_sha256 = hex::encode(Sha256::digest(&target_bytes));
        let target_meta = json!({
            "length": target_bytes.len(),
            "hashes": { "sha256": target_sha256 }
        });
        let targets_role = json!({
            "_type": "targets",
            "spec_version": "1.0.0",
            "version": targets_version,
            "expires": if expired { "2000-01-01T00:00:00Z" } else { EXPIRES },
            "targets": { target_path.clone(): target_meta }
        });
        let targets = signed(&targets_role, &keys);
        let targets_sha = hex::encode(Sha256::digest(&targets));
        let snapshot_role = json!({
            "_type": "snapshot",
            "spec_version": "1.0.0",
            "version": snapshot_version,
            "expires": if expired { "2000-01-01T00:00:00Z" } else { EXPIRES },
            "meta": {
                "targets.json": {
                    "version": targets_version,
                    "length": targets.len(),
                    "hashes": { "sha256": targets_sha }
                }
            }
        });
        let snapshot = signed(&snapshot_role, &keys);
        let snapshot_sha = hex::encode(Sha256::digest(&snapshot));
        let timestamp_role = json!({
            "_type": "timestamp",
            "spec_version": "1.0.0",
            "version": timestamp_version,
            "expires": if expired { "2000-01-01T00:00:00Z" } else { EXPIRES },
            "meta": {
                "snapshot.json": {
                    "version": snapshot_version,
                    "length": snapshot.len(),
                    "hashes": { "sha256": snapshot_sha }
                }
            }
        });
        let timestamp = signed(&timestamp_role, &keys);
        let transport = MemoryTransport::new();
        transport
            .insert_path(&base, "timestamp.json", timestamp)
            .unwrap();
        transport
            .insert_path(
                &base,
                &format!("{snapshot_version}.snapshot.json"),
                snapshot,
            )
            .unwrap();
        transport
            .insert_path(&base, &format!("{targets_version}.targets.json"), targets)
            .unwrap();
        transport
            .insert_path(
                &base,
                &format!("{target_sha256}.{target_path}"),
                target_bytes,
            )
            .unwrap();
        for version in 2..=root_version {
            transport
                .insert_path(&base, &format!("{version}.root.json"), root(&keys, version))
                .unwrap();
        }
        Fixture {
            root: bootstrap_root,
            identity,
            base,
            transport,
            target_path,
            target_digest,
            target_sha256,
        }
    }

    pub(super) fn current(index_id: &str) -> Fixture {
        fixture(index_id, 1, 2, 2, 2, false)
    }

    pub(super) fn expired(index_id: &str) -> Fixture {
        fixture(index_id, 1, 1, 1, 1, true)
    }

    pub(super) fn generation(
        index_id: &str,
        timestamp_version: u64,
        snapshot_version: u64,
        targets_version: u64,
    ) -> Fixture {
        fixture(
            index_id,
            1,
            timestamp_version,
            snapshot_version,
            targets_version,
            false,
        )
    }

    pub(super) fn rotated(index_id: &str) -> Fixture {
        fixture(index_id, 2, 2, 2, 2, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Fixture;
    use std::num::NonZeroU64;
    use std::path::Path;
    use tempfile::tempdir;

    fn config_for(fixture: &Fixture, state_path: &Path, datastore_path: &Path) -> TrustConfig {
        TrustConfig::new(
            fixture.identity.clone(),
            fixture.root.clone(),
            fixture.base.clone(),
            fixture.base.clone(),
            state_path.to_owned(),
            datastore_path.to_owned(),
        )
        .unwrap()
    }

    #[test]
    fn root_fingerprint_is_exact_and_canonical() {
        let fp = root_fingerprint_from_bytes(b"root").unwrap();
        assert_eq!(fp.to_string().len(), 71);
        assert_eq!(TrustRootFingerprint::parse(&fp.to_string()).unwrap(), fp);
        assert!(TrustRootFingerprint::parse("sha256:00").is_err());
    }

    #[test]
    fn sparse_path_validates_algorithm_and_digest() {
        let digest = "11".repeat(32);
        assert_eq!(
            sparse_object_path("sha256", &digest).unwrap(),
            format!("objects/sha256/11/{digest}.json")
        );
        assert_eq!(
            sparse_object_path("blake3", &digest).unwrap(),
            format!("objects/blake3/11/{digest}.json")
        );
        assert!(matches!(
            sparse_object_path("sha1024", &digest),
            Err(Error::UnsupportedDigestAlgorithm { .. })
        ));
        assert!(matches!(
            sparse_object_path("sha256", "bad"),
            Err(Error::InvalidDigest { .. })
        ));
    }

    #[tokio::test]
    async fn state_write_is_atomic_on_failed_commit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = TrustedState {
            index_identity: IndexIdentity::new(
                "astrid".parse().unwrap(),
                root_fingerprint_from_bytes(b"root").unwrap(),
            ),
            root_version: 1,
            root_digest: "a".into(),
            timestamp_version: 1,
            timestamp_digest: "b".into(),
            snapshot_version: 1,
            snapshot_digest: "c".into(),
            targets_version: 1,
            targets_digest: "d".into(),
        };
        persist_state(&path, &state).await.unwrap();
        // Renaming over a directory is rejected; the existing state remains readable.
        let blocked = dir.path().join("blocked");
        tokio::fs::create_dir(&blocked).await.unwrap();
        let replacement = TrustedState {
            root_version: NonZeroU64::new(2).unwrap().get(),
            ..state.clone()
        };
        let result = persist_state(&blocked, &replacement).await;
        assert!(result.is_err());
        assert_eq!(read_state(&path).await.unwrap(), Some(state));
    }

    #[tokio::test]
    async fn state_lock_serializes_concurrent_writers() {
        let dir = tempdir().unwrap();
        let path = state_lock_path(&dir.path().join("state.json"));
        let first = tokio::task::spawn_blocking({
            let path = path.clone();
            move || acquire_state_lock(&path, Duration::from_secs(1)).unwrap()
        })
        .await
        .unwrap();
        let second = tokio::task::spawn_blocking({
            let path = path.clone();
            move || acquire_state_lock(&path, Duration::from_millis(20))
        })
        .await
        .unwrap();
        assert!(matches!(second, Err(Error::Timeout { .. })));
        drop(first);
        let third =
            tokio::task::spawn_blocking(move || acquire_state_lock(&path, Duration::from_secs(1)))
                .await
                .unwrap();
        assert!(third.is_ok());
    }

    #[test]
    fn monotonic_versions_reject_every_role_rollback() {
        let fp = root_fingerprint_from_bytes(b"root").unwrap();
        let previous = TrustedState {
            index_identity: IndexIdentity::new("astrid".parse().unwrap(), fp.clone()),
            root_version: 2,
            root_digest: "a".into(),
            timestamp_version: 4,
            timestamp_digest: "b".into(),
            snapshot_version: 3,
            snapshot_digest: "c".into(),
            targets_version: 3,
            targets_digest: "d".into(),
        };
        let current = TrustedState {
            root_version: 2,
            timestamp_version: 3,
            snapshot_version: 3,
            targets_version: 3,
            ..previous.clone()
        };
        assert!(matches!(
            check_monotonic(&previous, &current),
            Err(Error::Rollback { role, .. }) if role == "timestamp"
        ));
    }

    #[tokio::test]
    async fn verified_index_reads_content_addressed_sparse_object() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::current("astrid");
        let index = load(
            config_for(
                &fixture,
                &dir.path().join("state.json"),
                &dir.path().join("datastore"),
            ),
            fixture.transport.clone(),
        )
        .await
        .unwrap();

        assert_eq!(index.state().timestamp_version, 2);
        assert_eq!(index.state().snapshot_version, 2);
        assert_eq!(
            index
                .read_sparse_object("blake3", &fixture.target_digest)
                .await
                .unwrap(),
            b"astrid-capsule"
        );
    }

    #[tokio::test]
    async fn expired_metadata_is_rejected_by_default_but_explicit_offline_policy_can_allow_it() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::expired("astrid");
        let state_path = dir.path().join("state.json");
        let strict = config_for(&fixture, &state_path, &dir.path().join("strict-datastore"));
        assert!(matches!(
            load(strict, fixture.transport.clone()).await,
            Err(Error::Expired { .. })
        ));

        let offline = config_for(&fixture, &state_path, &dir.path().join("offline-datastore"))
            .mode(VerificationMode::Offline(OfflinePolicy::AllowExpired));
        assert!(load(offline, fixture.transport.clone()).await.is_ok());
    }

    #[tokio::test]
    async fn old_timestamp_is_rejected_against_persisted_high_water_mark() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let first = crate::fixture::current("astrid");
        load(
            config_for(&first, &state_path, &dir.path().join("first-datastore")),
            first.transport,
        )
        .await
        .unwrap();

        let old = crate::fixture::generation("astrid", 1, 2, 2);
        assert!(matches!(
            load(
                config_for(&old, &state_path, &dir.path().join("old-datastore")),
                old.transport,
            )
            .await,
            Err(Error::Rollback { role, .. }) if role == "timestamp"
        ));
    }

    #[tokio::test]
    async fn old_snapshot_under_fresh_timestamp_is_rejected() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let first = crate::fixture::current("astrid");
        load(
            config_for(&first, &state_path, &dir.path().join("first-datastore")),
            first.transport,
        )
        .await
        .unwrap();

        let old = crate::fixture::generation("astrid", 3, 1, 1);
        assert!(matches!(
            load(
                config_for(&old, &state_path, &dir.path().join("old-datastore")),
                old.transport,
            )
            .await,
            Err(Error::Rollback { role, .. }) if role == "snapshot"
        ));
    }

    #[tokio::test]
    async fn mixed_generation_targets_are_rejected() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let first = crate::fixture::current("astrid");
        load(
            config_for(&first, &state_path, &dir.path().join("first-datastore")),
            first.transport,
        )
        .await
        .unwrap();

        let mixed = crate::fixture::generation("astrid", 3, 3, 1);
        assert!(matches!(
            load(
                config_for(&mixed, &state_path, &dir.path().join("mixed-datastore")),
                mixed.transport,
            )
            .await,
            Err(Error::Rollback { role, .. }) if role == "targets"
        ));
    }

    #[tokio::test]
    async fn tampered_target_is_rejected_by_tuf_and_wrapper_digest_check() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::current("astrid");
        let index = load(
            config_for(
                &fixture,
                &dir.path().join("state.json"),
                &dir.path().join("datastore"),
            ),
            fixture.transport.clone(),
        )
        .await
        .unwrap();
        let target_url = fixture
            .base
            .join(&format!(
                "{}.{}",
                fixture.target_sha256, fixture.target_path
            ))
            .unwrap();
        fixture.transport.insert(&target_url, b"tampered");

        let result = index
            .read_sparse_object("blake3", &fixture.target_digest)
            .await;
        assert!(matches!(result, Err(Error::DigestMismatch { .. })));
    }

    #[tokio::test]
    async fn oversized_metadata_is_rejected_before_unbounded_parse() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::current("astrid");
        let limits = Limits {
            max_timestamp_bytes: 1,
            ..Limits::default()
        };
        let config = config_for(
            &fixture,
            &dir.path().join("state.json"),
            &dir.path().join("datastore"),
        )
        .limits(limits);
        let result = load(config, fixture.transport).await;
        assert!(matches!(result, Err(Error::MetadataTooLarge { .. })));
    }

    #[tokio::test]
    async fn declared_snapshot_length_cannot_bypass_wrapper_bound() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::current("astrid");
        let limits = Limits {
            max_snapshot_bytes: 1,
            ..Limits::default()
        };
        let config = config_for(
            &fixture,
            &dir.path().join("state.json"),
            &dir.path().join("datastore"),
        )
        .limits(limits);
        let result = load(config, fixture.transport).await;
        assert!(matches!(
            result,
            Err(Error::MetadataTooLarge {
                role: "snapshot",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn root_rotation_requires_and_accepts_a_consecutive_signed_chain() {
        let dir = tempdir().unwrap();
        let fixture = crate::fixture::rotated("astrid");
        let index = load(
            config_for(
                &fixture,
                &dir.path().join("state.json"),
                &dir.path().join("datastore"),
            ),
            fixture.transport,
        )
        .await
        .unwrap();
        assert_eq!(index.root().signed.version.get(), 2);
        assert_eq!(index.state().root_version, 2);
        // `root_bytes` reports the final trusted role, not the bootstrap bytes
        // supplied to `TrustConfig`.  The bootstrap fingerprint remains the
        // stable source identity while the signed chain advances this state.
        assert_ne!(index.root_bytes(), fixture.root.as_slice());
    }

    #[tokio::test]
    async fn state_cannot_be_reused_for_a_different_index_root() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let first = crate::fixture::current("astrid");
        load(
            config_for(&first, &state_path, &dir.path().join("first-datastore")),
            first.transport,
        )
        .await
        .unwrap();

        let different = crate::fixture::current("aos");
        assert!(matches!(
            load(
                config_for(
                    &different,
                    &state_path,
                    &dir.path().join("different-datastore"),
                ),
                different.transport,
            )
            .await,
            Err(Error::StateIdentityMismatch { .. })
        ));
    }
}
