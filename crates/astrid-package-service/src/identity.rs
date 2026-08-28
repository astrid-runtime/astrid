use crate::digest::{Blake3Digest, Sha256Digest};
use crate::error::{PackageServiceError, PackageServiceResult};
use std::num::{NonZeroU32, NonZeroU64};

macro_rules! opaque32 {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            #[doc = concat!("Creates a validated ", stringify!($name), " from 32 bytes.")]
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[doc = "Returns the immutable canonical bytes."]
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

opaque32!(
    Nonce,
    "Cryptographically random, globally unique operation nonce."
);
opaque32!(
    ComponentIdentity,
    "Authenticated admitted-service component identity."
);
opaque32!(
    PackageObject,
    "Immutable owner-neutral package object identity."
);
opaque32!(
    AuthorityIssuerIdentity,
    "Immutable authority issuer or issuer-policy identity."
);

/// Private protocol version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(NonZeroU32);

/// Canonical installed-state schema version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StateSchemaVersion(NonZeroU32);

/// Canonical operation-journal schema version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JournalSchemaVersion(NonZeroU32);

/// Immutable admitted-service generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceGeneration(NonZeroU64);

impl ProtocolVersion {
    /// Constructs a protocol version.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the numeric protocol version.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

impl StateSchemaVersion {
    /// Constructs a state schema version.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the numeric schema version.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

impl JournalSchemaVersion {
    /// Constructs a journal schema version.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the numeric journal schema version.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

impl ServiceGeneration {
    /// Constructs a positive service generation.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(&self) -> u64 {
        self.0.get()
    }

    /// Returns the underlying nonzero generation.
    #[must_use]
    pub const fn as_non_zero(&self) -> NonZeroU64 {
        self.0
    }
}

/// Artifact format identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactFormatVersion(NonZeroU32);

/// Manifest format identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ManifestFormatVersion(NonZeroU32);

impl ArtifactFormatVersion {
    /// Constructs a positive format version.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the numeric format version.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

impl ManifestFormatVersion {
    /// Constructs a positive format version.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the numeric format version.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }
}

/// Exact-byte artifact identity produced by the trusted staging boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactIdentity {
    format_version: ArtifactFormatVersion,
    size_bytes: NonZeroU64,
    sha256: Sha256Digest,
    blake3: Blake3Digest,
}

impl ArtifactIdentity {
    /// Binds both mandatory exact-byte digests and the exact size.
    pub fn new(
        format_version: ArtifactFormatVersion,
        size_bytes: NonZeroU64,
        sha256: Sha256Digest,
        blake3: Blake3Digest,
    ) -> PackageServiceResult<Self> {
        if sha256.as_bytes() == &[0; 32] || blake3.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::InvalidValue("artifact identity"));
        }
        Ok(Self {
            format_version,
            size_bytes,
            sha256,
            blake3,
        })
    }

    /// Returns the exact artifact size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes.get()
    }

    /// Returns the SHA-256 identity.
    #[must_use]
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// Returns the BLAKE3 identity.
    #[must_use]
    pub const fn blake3(&self) -> &Blake3Digest {
        &self.blake3
    }

    pub(crate) const fn format_version(&self) -> u32 {
        self.format_version.get()
    }
}

/// Validated manifest identity bound to exact manifest bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestIdentity {
    format_version: ManifestFormatVersion,
    package_name: PackageName,
    package_version: PackageVersion,
    manifest_digest: Blake3Digest,
}

impl ManifestIdentity {
    /// Constructs a bounded, validated manifest identity.
    pub fn new(
        format_version: ManifestFormatVersion,
        package_name: PackageName,
        package_version: PackageVersion,
        manifest_digest: Blake3Digest,
    ) -> PackageServiceResult<Self> {
        if manifest_digest.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::InvalidValue("manifest identity"));
        }
        Ok(Self {
            format_version,
            package_name,
            package_version,
            manifest_digest,
        })
    }

    /// Returns the validated package name.
    #[must_use]
    pub const fn package_name(&self) -> &PackageName {
        &self.package_name
    }

    /// Returns the validated package version.
    #[must_use]
    pub const fn package_version(&self) -> &PackageVersion {
        &self.package_version
    }

    pub(crate) const fn format_version(&self) -> u32 {
        self.format_version.get()
    }

    pub(crate) const fn manifest_digest(&self) -> &Blake3Digest {
        &self.manifest_digest
    }
}

/// Artifact identities and immutable content root after full validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedArtifact {
    artifact: ArtifactIdentity,
    manifest: ManifestIdentity,
    content_root: Blake3Digest,
    provenance: ProvenanceEvidence,
}

/// Bounded provenance evidence used for attribution only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceEvidence {
    class: ProvenanceClass,
    evidence: Blake3Digest,
    bounded_evidence: BoundedEvidence,
}

/// Neutral provenance class used only for attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceClass {
    /// Artifact already resident in trusted service storage.
    LocalArtifact,
    /// Artifact produced by an authenticated build boundary.
    BuildOutput,
    /// Artifact admitted by an authenticated publication boundary.
    PublishedArtifact,
    /// Artifact admitted by an authenticated distribution boundary.
    DistributionArtifact,
}

impl ProvenanceClass {
    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::LocalArtifact => 1,
            Self::BuildOutput => 2,
            Self::PublishedArtifact => 3,
            Self::DistributionArtifact => 4,
        }
    }
}

impl ProvenanceEvidence {
    /// Constructs attribution evidence without interpreting its bounded bytes.
    pub fn new(
        class: ProvenanceClass,
        evidence: Blake3Digest,
        bounded_evidence: BoundedEvidence,
    ) -> PackageServiceResult<Self> {
        if evidence.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::InvalidValue("provenance evidence"));
        }
        Ok(Self {
            class,
            evidence,
            bounded_evidence,
        })
    }

    pub(crate) const fn class(&self) -> ProvenanceClass {
        self.class
    }

    pub(crate) const fn evidence(&self) -> &Blake3Digest {
        &self.evidence
    }

    pub(crate) const fn bounded_evidence(&self) -> &BoundedEvidence {
        &self.bounded_evidence
    }
}

/// Bounded opaque bytes preserved by the trusted validation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedEvidence(Vec<u8>);

impl BoundedEvidence {
    /// Maximum protocol ceiling for attribution evidence retained in state.
    ///
    /// This is a format boundary, not an operator tuning knob. A deployment may
    /// supply fewer bytes; larger evidence remains outside this contract.
    pub const MAX_BYTES: usize = 4_096;

    /// Validates and owns an evidence byte vector.
    pub fn new(bytes: Vec<u8>) -> PackageServiceResult<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(PackageServiceError::InvalidValue("bounded evidence"));
        }
        Ok(Self(bytes))
    }

    /// Returns the preserved evidence bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl ValidatedArtifact {
    /// Binds an already validated artifact to immutable content and provenance.
    pub fn new(
        artifact: ArtifactIdentity,
        manifest: ManifestIdentity,
        content_root: Blake3Digest,
        provenance: ProvenanceEvidence,
    ) -> PackageServiceResult<Self> {
        if content_root.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::InvalidValue("content root"));
        }
        Ok(Self {
            artifact,
            manifest,
            content_root,
            provenance,
        })
    }

    /// Returns the exact-byte artifact identity.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactIdentity {
        &self.artifact
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub const fn manifest(&self) -> &ManifestIdentity {
        &self.manifest
    }

    /// Returns the immutable content root.
    #[must_use]
    pub const fn content_root(&self) -> &Blake3Digest {
        &self.content_root
    }

    /// Returns attribution-only provenance evidence.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceEvidence {
        &self.provenance
    }
}

/// Bounded package-name syntax used only by manifest identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageName(String);

/// Bounded package-version text used only by manifest identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageVersion(String);

impl PackageName {
    /// Validates a lowercase ASCII package name of at most 64 bytes.
    pub fn new(value: &str) -> PackageServiceResult<Self> {
        validate_bounded_ascii(value, 64, false)?;
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        }) {
            return Err(PackageServiceError::InvalidValue("package name"));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PackageVersion {
    /// Validates printable, non-whitespace ASCII of at most 64 bytes.
    pub fn new(value: &str) -> PackageServiceResult<Self> {
        validate_bounded_ascii(value, 64, false)?;
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(PackageServiceError::InvalidValue("package version"));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_bounded_ascii(
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> PackageServiceResult<()> {
    if value.len() > maximum
        || (value.is_empty() && !allow_empty)
        || !value.bytes().all(|byte| byte.is_ascii())
    {
        return Err(PackageServiceError::InvalidValue("bounded ASCII"));
    }
    Ok(())
}

/// The protocol version understood by this model.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(match NonZeroU32::new(1) {
    Some(value) => value,
    None => panic!("protocol one is non-zero"),
});

/// Canonical installed-state schema version understood by this model.
pub const STATE_SCHEMA_VERSION: StateSchemaVersion =
    StateSchemaVersion::new(match NonZeroU32::new(1) {
        Some(value) => value,
        None => panic!("schema one is non-zero"),
    });

/// Canonical operation-journal schema version understood by this model.
pub const JOURNAL_SCHEMA_VERSION: JournalSchemaVersion =
    JournalSchemaVersion::new(match NonZeroU32::new(1) {
        Some(value) => value,
        None => panic!("journal schema one is non-zero"),
    });
