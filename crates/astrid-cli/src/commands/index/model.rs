//! Data model for configured Capsule Index sources.
//!
//! The model is deliberately independent from clap and from a concrete TUF
//! implementation. A source stores an immutable trust anchor and the last
//! verified metadata snapshot; the verifier used to produce that snapshot is
//! supplied by the caller.

use std::path::{Component, Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use super::{IndexError, metadata_digest, root_fingerprint};

/// Current on-disk schema version.
pub(crate) const CONFIG_SCHEMA_VERSION: u32 = 1;

/// The immutable identifier reserved for the official Astrid Index.
pub(crate) const BUILTIN_INDEX_ID: &str = "astrid";

/// The root trust anchor pinned for one Index source.
///
/// `bytes_b64` is always persisted, even when the operator supplied a file
/// path. path is retained as provenance for diagnostics and for an explicit
/// future rotation command; it is never followed during ordinary metadata
/// refresh. Persisting the bytes prevents a deleted or replaced root file
/// from silently changing the trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PinnedRoot {
    /// Base64-encoded canonical TUF root bytes.
    pub(crate) bytes_b64: String,
    /// Optional operator-supplied path retained for provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    /// Tagged SHA-256 digest of the exact bytes: sha256:<64 lowercase hex>.
    pub(crate) fingerprint: String,
}

impl PinnedRoot {
    /// Build a root pin from bytes and a caller-supplied fingerprint.
    pub(crate) fn from_bytes(bytes: &[u8], fingerprint: &str) -> Result<Self, IndexError> {
        let fingerprint = normalize_root_fingerprint(fingerprint)?;
        verify_fingerprint(bytes, &fingerprint)?;
        Ok(Self {
            bytes_b64: BASE64.encode(bytes),
            path: None,
            fingerprint,
        })
    }

    /// Build a root pin from a path, retaining both the path and a byte
    /// snapshot. The path is validated before it is persisted.
    pub(crate) fn from_path(
        path: impl Into<PathBuf>,
        fingerprint: &str,
    ) -> Result<Self, IndexError> {
        let path = path.into();
        validate_root_path(&path)?;
        let bytes = std::fs::read(&path).map_err(|source| IndexError::RootRead {
            path: path.clone(),
            source,
        })?;
        let mut root = Self::from_bytes(&bytes, fingerprint)?;
        root.path = Some(path.to_string_lossy().into_owned());
        Ok(root)
    }

    /// Decode the pinned root bytes.
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, IndexError> {
        BASE64
            .decode(self.bytes_b64.as_bytes())
            .map_err(|source| IndexError::CorruptRootEncoding { source })
    }

    /// Validate all serialized fields, including the byte/fingerprint bind.
    pub(crate) fn validate(&self) -> Result<(), IndexError> {
        let bytes = self.bytes()?;
        let fingerprint = normalize_root_fingerprint(&self.fingerprint)?;
        // Persist only the tagged protocol spelling. Accepting a bare value
        // here would make collision checks depend on how two operators typed
        // the same SHA-256 digest and would drift from LockRecord identity.
        if fingerprint != self.fingerprint {
            return Err(IndexError::InvalidFingerprint(self.fingerprint.clone()));
        }
        verify_fingerprint(&bytes, &fingerprint)?;
        if let Some(path) = self.path.as_deref() {
            validate_root_path(Path::new(path))?;
        }
        Ok(())
    }
}

/// The last metadata snapshot that passed a real TUF verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MetadataSnapshot {
    /// TUF metadata version (for rollback/continuity checks in the verifier).
    pub(crate) version: u64,
    /// Base64-encoded verified metadata bytes.
    pub(crate) bytes_b64: String,
    /// Digest of the exact verified bytes.
    pub(crate) digest: String,
}

impl MetadataSnapshot {
    /// Construct and validate a snapshot returned by a verifier adapter.
    pub(crate) fn new(version: u64, bytes: &[u8], digest: &str) -> Result<Self, IndexError> {
        let digest = normalize_fingerprint(digest)?;
        let expected = metadata_digest(bytes);
        if digest != expected {
            return Err(IndexError::MetadataDigestMismatch {
                expected,
                supplied: digest,
            });
        }
        Ok(Self {
            version,
            bytes_b64: BASE64.encode(bytes),
            digest,
        })
    }

    /// Decode the verified metadata bytes.
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, IndexError> {
        BASE64
            .decode(self.bytes_b64.as_bytes())
            .map_err(|source| IndexError::CorruptMetadataEncoding { source })
    }

    /// Validate a persisted snapshot.
    pub(crate) fn validate(&self) -> Result<(), IndexError> {
        let bytes = self.bytes()?;
        let digest = normalize_fingerprint(&self.digest)?;
        if digest != metadata_digest(&bytes) {
            return Err(IndexError::MetadataDigestMismatch {
                expected: metadata_digest(&bytes),
                supplied: digest,
            });
        }
        Ok(())
    }
}

/// A configured Capsule Index source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct IndexSource {
    /// Stable Index identity. This is not a display label.
    pub(crate) id: String,
    /// Canonical Pages base URL.
    pub(crate) base_url: String,
    /// Pinned TUF root trust anchor.
    pub(crate) root: PinnedRoot,
    /// Whether this source participates in resolution.
    pub(crate) enabled: bool,
    /// Explicit resolution priority; lower numbers win.
    pub(crate) priority: i32,
    /// Marker for the compiled-in official source.
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) built_in: bool,
    /// Last verified metadata, if this source has been refreshed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<MetadataSnapshot>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !value
}

impl IndexSource {
    /// Validate an untrusted source record.
    pub(crate) fn validate(&self) -> Result<(), IndexError> {
        validate_index_id(&self.id)?;
        let canonical_url = validate_base_url(&self.base_url)?;
        if canonical_url != self.base_url {
            return Err(IndexError::NonCanonicalUrl {
                supplied: self.base_url.clone(),
                canonical: canonical_url,
            });
        }
        self.root.validate()?;
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        Ok(())
    }

    /// Canonical identity key used for collision checks.
    pub(crate) fn identity_key(&self) -> &str {
        &self.id
    }

    /// Canonical URL key used for duplicate-source checks.
    pub(crate) fn url_key(&self) -> &str {
        &self.base_url
    }

    /// Convert this configured source to the protocol identity used by
    /// `LockRecord`. This is the integration point that prevents CLI source
    /// identity and lockfile identity from drifting.
    pub(crate) fn protocol_identity(
        &self,
    ) -> Result<astrid_capsule_index::IndexIdentity, IndexError> {
        let id = astrid_capsule_index::IndexId::new(self.id.clone())
            .map_err(|_| IndexError::InvalidId(self.id.clone()))?;
        let trust_root = astrid_capsule_index::TrustRootFingerprint::parse(&self.root.fingerprint)
            .map_err(|_| IndexError::InvalidFingerprint(self.root.fingerprint.clone()))?;
        Ok(astrid_capsule_index::IndexIdentity::new(id, trust_root))
    }
}

/// The serialized index-source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct IndexConfig {
    /// Schema version for forwards-incompatible changes.
    pub(crate) schema_version: u32,
    /// Sources sorted by stable ID before serialization.
    #[serde(default)]
    pub(crate) sources: Vec<IndexSource>,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            sources: Vec::new(),
        }
    }
}

impl IndexConfig {
    /// Validate schema and all source collision invariants.
    pub(crate) fn validate(&self) -> Result<(), IndexError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(IndexError::UnsupportedSchema {
                found: self.schema_version,
                supported: CONFIG_SCHEMA_VERSION,
            });
        }

        let mut by_id = std::collections::BTreeSet::new();
        let mut by_root = std::collections::BTreeMap::<String, String>::new();
        let mut by_url = std::collections::BTreeMap::<String, String>::new();
        for source in &self.sources {
            source.validate()?;
            if !by_id.insert(source.identity_key().to_owned()) {
                return Err(IndexError::DuplicateId(source.id.clone()));
            }
            if let Some(previous) =
                by_root.insert(source.root.fingerprint.clone(), source.id.clone())
                && previous != source.id
            {
                return Err(IndexError::DuplicateTrustRoot {
                    fingerprint: source.root.fingerprint.clone(),
                    first: previous,
                    second: source.id.clone(),
                });
            }
            if let Some(previous) = by_url.insert(source.url_key().to_owned(), source.id.clone())
                && previous != source.id
            {
                return Err(IndexError::DuplicateUrl {
                    url: source.base_url.clone(),
                    first: previous,
                    second: source.id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Return a stable, canonical TOML representation.
    pub(crate) fn to_stable_toml(&self) -> Result<String, IndexError> {
        let mut normalized = self.clone();
        normalized
            .sources
            .sort_by(|left, right| left.id.cmp(&right.id));
        normalized.validate()?;
        toml::to_string_pretty(&normalized).map_err(|source| IndexError::Serialize { source })
    }
}

/// Validate an Index ID and reject path-like or ambiguous names.
pub(crate) fn validate_index_id(id: &str) -> Result<(), IndexError> {
    if id.is_empty() {
        return Err(IndexError::InvalidId(id.to_owned()));
    }
    // Keep the CLI grammar exactly aligned with the protocol's IndexId, which
    // is also what LockRecord serializes and verifies.
    if astrid_capsule_index::IndexId::new(id.to_owned()).is_err() {
        return Err(IndexError::InvalidId(id.to_owned()));
    }
    if id != id.trim() || id != id.to_ascii_lowercase() {
        return Err(IndexError::AmbiguousId(id.to_owned()));
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\\') {
        return Err(IndexError::AmbiguousId(id.to_owned()));
    }
    let id_bytes = id.as_bytes();
    if !id_bytes.iter().copied().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    }) || !id_bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !id_bytes.last().is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(IndexError::InvalidId(id.to_owned()));
    }
    Ok(())
}

/// Validate and canonicalize a Pages base URL.
pub(crate) fn validate_base_url(value: &str) -> Result<String, IndexError> {
    if value.is_empty() || value.contains('\\') {
        return Err(IndexError::InvalidUrl(value.to_owned()));
    }
    // `url::Url` normalizes literal dot segments while parsing (for example,
    // `/a/../b` becomes `/b`). Inspect the caller's spelling first so an
    // attacker cannot smuggle traversal through that normalization.
    if raw_url_path_has_traversal(value) {
        return Err(IndexError::UrlPathTraversal(value.to_owned()));
    }
    let parsed = url::Url::parse(value).map_err(|source| IndexError::UrlParse {
        value: value.to_owned(),
        source,
    })?;
    if parsed.host_str().is_none() || parsed.host_str() == Some("") {
        return Err(IndexError::InvalidUrl(value.to_owned()));
    }
    let scheme = parsed.scheme().to_owned();
    let loopback_http = scheme == "http" && parsed.host_str().is_some_and(is_loopback_host);
    if scheme != "https" && !loopback_http {
        return Err(IndexError::InsecureUrl(value.to_owned()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(IndexError::UrlCredentials(value.to_owned()));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(IndexError::UrlQueryOrFragment(value.to_owned()));
    }
    if parsed.cannot_be_a_base() {
        return Err(IndexError::InvalidUrl(value.to_owned()));
    }
    if parsed
        .path_segments()
        .is_some_and(|mut segments| segments.any(|segment| segment == "." || segment == ".."))
        || parsed.path().to_ascii_lowercase().contains("%2e")
        || parsed.path().to_ascii_lowercase().contains("%2f")
        || parsed.path().to_ascii_lowercase().contains("%5c")
        || parsed.path().to_ascii_lowercase().contains("%25")
    {
        return Err(IndexError::UrlPathTraversal(value.to_owned()));
    }
    // A base URL must name a directory-like Pages prefix, never an opaque
    // filename. The root URL (https://host) is valid and normalizes to /.
    let mut canonical = parsed;
    if (scheme == "https" && canonical.port() == Some(443))
        || (scheme == "http" && canonical.port() == Some(80))
    {
        // Treat explicit default ports and omitted default ports as one source
        // identity, avoiding duplicate Pages registrations under equivalent
        // URLs.
        let _ = canonical.set_port(None);
    }
    if !canonical.path().is_empty() && !canonical.path().ends_with('/') {
        let path = format!("{}/", canonical.path());
        canonical.set_path(&path);
    }
    Ok(canonical.to_string())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn raw_url_path_has_traversal(value: &str) -> bool {
    let Some((_, authority_and_path)) = value.split_once("://") else {
        return false;
    };
    let Some(path_start) = authority_and_path.find('/') else {
        return false;
    };
    let path = authority_and_path[path_start..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
        || path.to_ascii_lowercase().contains("%2e")
        || path.to_ascii_lowercase().contains("%2f")
        || path.to_ascii_lowercase().contains("%5c")
        || path.to_ascii_lowercase().contains("%25")
}

/// Reject root paths that can escape an explicitly selected config area.
pub(crate) fn validate_root_path(path: &Path) -> Result<(), IndexError> {
    if path.as_os_str().is_empty()
        || path.to_string_lossy().contains('\\')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(IndexError::PathTraversal(path.to_path_buf()));
    }
    Ok(())
}

/// Normalize a metadata digest to a supported canonical form.
pub(crate) fn normalize_fingerprint(value: &str) -> Result<String, IndexError> {
    let value = value.trim();
    let (algorithm, hex_value) = value.split_once(':').unwrap_or(("blake3", value));
    if !matches!(algorithm, "sha256" | "blake3")
        || hex_value.len() != 64
        || !hex_value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex_value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(IndexError::InvalidFingerprint(value.to_owned()));
    }
    Ok(format!("{algorithm}:{hex_value}"))
}

/// Normalize the tagged SHA-256 trust-root fingerprint used by `IndexIdentity`.
pub(crate) fn normalize_root_fingerprint(value: &str) -> Result<String, IndexError> {
    let value = value.trim();
    let tagged = if value.contains(':') {
        value.to_owned()
    } else {
        format!("sha256:{value}")
    };
    if !tagged.starts_with("sha256:") {
        return Err(IndexError::InvalidFingerprint(value.to_owned()));
    }
    let canonical = normalize_fingerprint(&tagged)?;
    astrid_capsule_index::TrustRootFingerprint::parse(&canonical)
        .map(|fingerprint| fingerprint.to_string())
        .map_err(|_| IndexError::InvalidFingerprint(value.to_owned()))
}

/// Verify a supplied root fingerprint against exact bytes.
pub(crate) fn verify_fingerprint(bytes: &[u8], fingerprint: &str) -> Result<(), IndexError> {
    let expected = root_fingerprint(bytes);
    if expected != fingerprint {
        return Err(IndexError::FingerprintMismatch {
            expected,
            supplied: fingerprint.to_owned(),
        });
    }
    Ok(())
}
