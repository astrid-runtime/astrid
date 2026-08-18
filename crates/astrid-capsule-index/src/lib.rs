#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unreachable_pub)]
#![forbid(unsafe_code)]

//! Foundational domain types for an Astrid Capsule Index.
//!
//! The index is an append-only collection of sealed publication records and
//! lifecycle events.  A publication's identity is its digest, while its
//! coordinate (`@namespace/name` plus a canonical SemVer) can be occupied only
//! once by a given index.  This crate deliberately keeps all values pure and
//! deterministic: no clock, filesystem, network, or signing-key dependency is
//! needed to validate or resolve an index snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use semver::{Version, VersionReq};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const PUBLICATION_DOMAIN: &[u8] = b"astrid:capsule-index:publication:v1\0";
const PUBLICATION_SCHEMA_V1: &str = "publication-v1";
const EVENT_DOMAIN: &[u8] = b"astrid:capsule-index:event:v1\0";
const EVENT_SCHEMA_V1: &str = "event-envelope-v1";

/// Errors returned by the Capsule Index domain types.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IndexError {
    /// A value was empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Human-readable kind of value.
        kind: &'static str,
    },
    /// A value contains a character outside its grammar.
    #[error("invalid {kind} `{value}`")]
    InvalidValue {
        /// Human-readable kind of value.
        kind: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A SemVer value could not be parsed.
    #[error("invalid semantic version `{value}`: {reason}")]
    InvalidVersion {
        /// Rejected version.
        value: String,
        /// Parser explanation.
        reason: String,
    },
    /// Build metadata is not part of the canonical publication version.
    #[error("semantic version `{0}` contains build metadata")]
    BuildMetadata(String),
    /// A digest has an unknown algorithm, malformed encoding, or wrong size.
    #[error("invalid digest `{0}`")]
    InvalidDigest(String),
    /// An immutable publication field was omitted.
    #[error("publication field `{0}` is required")]
    MissingField(&'static str),
    /// A serialized publication's digest did not match its fields.
    #[error("publication digest does not match the sealed fields")]
    PublicationDigestMismatch,
    /// A publication under an occupied coordinate changed its immutable bytes.
    #[error("publication equivocation at {0}")]
    Equivocation(Box<PublicationKey>),
    /// An event targeted another index.
    #[error("event belongs to index `{event}`, not `{expected}`")]
    WrongIndex {
        /// Index found in the candidate/event.
        event: IndexId,
        /// Index expected by this ledger/resolver.
        expected: IndexId,
    },
    /// A lifecycle event was not valid after the current state.
    #[error("invalid lifecycle transition for {publication}: {reason}")]
    InvalidTransition {
        /// The affected publication.
        publication: Box<PublicationKey>,
        /// Why the transition was rejected.
        reason: &'static str,
    },
    /// An event references a publication absent from the index.
    #[error("publication {0} is not present in the index")]
    UnknownPublication(Box<PublicationKey>),
    /// An event contains invalid text or a duplicate append-only item.
    #[error("invalid index event: {0}")]
    InvalidEvent(&'static str),
    /// A lock is bound to a different index trust identity.
    #[error("lock is bound to a different index identity")]
    LockIndexMismatch,
    /// A lock does not match the immutable record at its coordinate.
    #[error("lock does not match the publication at {0}")]
    LockMismatch(Box<PublicationKey>),
    /// A locked publication cannot be used because it was revoked.
    #[error("locked publication {0} is revoked")]
    LockedPublicationRevoked(Box<PublicationKey>),
    /// A resolution request did not find a candidate.
    #[error("no compatible publication for {coordinate}")]
    NoMatchingPublication {
        /// Coordinate that had no eligible candidate.
        coordinate: Coordinate,
    },
}

/// Result alias used by the protocol types.
pub type IndexResult<T> = Result<T, IndexError>;

fn validate_ascii_token(value: &str, kind: &'static str) -> IndexResult<()> {
    if value.is_empty() {
        return Err(IndexError::Empty { kind });
    }
    if !value.is_ascii() || value.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(IndexError::InvalidValue {
            kind,
            value: value.to_owned(),
        });
    }
    let first = value.as_bytes()[0];
    if !first.is_ascii_alphanumeric()
        || value
            .as_bytes()
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && *b != b'-' && *b != b'_' && *b != b'.')
        || value == "."
        || value == ".."
    {
        return Err(IndexError::InvalidValue {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_name(value: &str, kind: &'static str) -> IndexResult<()> {
    if value.is_empty()
        || value.len() > 63
        || !value.is_ascii()
        || value
            .chars()
            .any(|character| character.is_ascii_uppercase())
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || !value.as_bytes()[0].is_ascii_lowercase()
        || value.as_bytes().last() == Some(&b'-')
    {
        return Err(IndexError::InvalidValue {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// A stable identifier for a Capsule Index.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndexId(String);

impl IndexId {
    /// Creates a validated lowercase ASCII index identifier.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        validate_ascii_token(&value, "index id")?;
        Ok(Self(value))
    }

    /// Returns the canonical identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IndexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for IndexId {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for IndexId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IndexId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A cryptographic fingerprint identifying the trust root used by an index.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustRootFingerprint(Digest);

impl TrustRootFingerprint {
    /// Wraps a validated digest as a trust-root fingerprint.
    pub fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// Parses a tagged digest (`sha256:<lowercase hex>`), or a bare SHA-256
    /// hexadecimal value for compatibility with common root-fingerprint files.
    pub fn parse(value: &str) -> IndexResult<Self> {
        if value.contains(':') {
            Ok(Self(Digest::parse(value)?))
        } else {
            Ok(Self(Digest::parse(&format!("sha256:{value}"))?))
        }
    }

    /// Returns the underlying digest.
    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for TrustRootFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for TrustRootFingerprint {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for TrustRootFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TrustRootFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// The stable trust identity of one index source.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct IndexIdentity {
    /// Stable index identifier.
    pub id: IndexId,
    /// Fingerprint of the index trust root.
    pub trust_root: TrustRootFingerprint,
}

impl IndexIdentity {
    /// Creates an index identity.
    pub fn new(id: IndexId, trust_root: TrustRootFingerprint) -> Self {
        Self { id, trust_root }
    }
}

/// Lowercase ASCII namespace portion of a capsule coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Namespace(String);

impl Namespace {
    /// Creates a validated namespace.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        validate_name(&value, "namespace")?;
        Ok(Self(value))
    }

    /// Returns the canonical namespace.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Namespace {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Namespace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Namespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Lowercase ASCII capsule-name portion of a coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapsuleName(String);

impl CapsuleName {
    /// Creates a validated capsule name.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        validate_name(&value, "capsule name")?;
        Ok(Self(value))
    }

    /// Returns the canonical capsule name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapsuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapsuleName {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for CapsuleName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CapsuleName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A namespaced capsule coordinate, displayed as `@namespace/name`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Coordinate {
    /// Namespace portion.
    pub namespace: Namespace,
    /// Capsule-name portion.
    pub name: CapsuleName,
}

impl Coordinate {
    /// Creates a coordinate from validated components.
    pub fn new(namespace: Namespace, name: CapsuleName) -> Self {
        Self { namespace, name }
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}/{}", self.namespace, self.name)
    }
}

impl FromStr for Coordinate {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(rest) = value.strip_prefix('@') else {
            return Err(IndexError::InvalidValue {
                kind: "coordinate",
                value: value.to_owned(),
            });
        };
        let mut parts = rest.split('/');
        let namespace = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if parts.next().is_some() || namespace.is_empty() || name.is_empty() {
            return Err(IndexError::InvalidValue {
                kind: "coordinate",
                value: value.to_owned(),
            });
        }
        Ok(Self::new(namespace.parse()?, name.parse()?))
    }
}

/// Canonical SemVer without build metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalSemVer(Version);

impl CanonicalSemVer {
    /// Parses a canonical SemVer value and rejects build metadata.
    pub fn parse(value: &str) -> IndexResult<Self> {
        let parsed = Version::parse(value).map_err(|error| IndexError::InvalidVersion {
            value: value.to_owned(),
            reason: error.to_string(),
        })?;
        if !parsed.build.is_empty() {
            return Err(IndexError::BuildMetadata(value.to_owned()));
        }
        Ok(Self(parsed))
    }

    /// Returns the wrapped SemVer.
    pub fn as_version(&self) -> &Version {
        &self.0
    }

    /// Returns whether this is a pre-release version.
    pub fn is_prerelease(&self) -> bool {
        !self.0.pre.is_empty()
    }
}

impl fmt::Display for CanonicalSemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for CanonicalSemVer {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalSemVer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalSemVer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Digest algorithms supported by index identity and publication records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    /// SHA-256, encoded as 32 bytes / 64 hexadecimal characters.
    Sha256,
    /// SHA-384, encoded as 48 bytes / 96 hexadecimal characters.
    Sha384,
    /// SHA-512, encoded as 64 bytes / 128 hexadecimal characters.
    Sha512,
    /// BLAKE3, encoded as 32 bytes / 64 hexadecimal characters.
    Blake3,
}

impl DigestAlgorithm {
    /// Parses a lowercase algorithm tag.
    pub fn parse(value: &str) -> IndexResult<Self> {
        match value {
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            "blake3" => Ok(Self::Blake3),
            _ => Err(IndexError::InvalidDigest(value.to_owned())),
        }
    }

    /// Returns the canonical lowercase algorithm tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }

    /// Returns the required byte length.
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Blake3 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    const fn hex_len(self) -> usize {
        self.byte_len() * 2
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// An algorithm-tagged, strictly lowercase hexadecimal digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    bytes: Vec<u8>,
}

impl Digest {
    /// Creates a digest from raw bytes, checking the algorithm's fixed size.
    pub fn from_bytes(algorithm: DigestAlgorithm, bytes: impl AsRef<[u8]>) -> IndexResult<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != algorithm.byte_len() {
            return Err(IndexError::InvalidDigest(format!(
                "{} digest has {} bytes, expected {}",
                algorithm,
                bytes.len(),
                algorithm.byte_len()
            )));
        }
        Ok(Self {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// Parses `algorithm:lowercase-hex`.
    pub fn parse(value: &str) -> IndexResult<Self> {
        let Some((algorithm, hex)) = value.split_once(':') else {
            return Err(IndexError::InvalidDigest(value.to_owned()));
        };
        let algorithm = DigestAlgorithm::parse(algorithm)?;
        if hex.len() != algorithm.hex_len()
            || !hex.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
            || hex.chars().any(|character| character.is_ascii_uppercase())
        {
            return Err(IndexError::InvalidDigest(value.to_owned()));
        }
        let mut bytes = Vec::with_capacity(algorithm.byte_len());
        for pair in hex.as_bytes().chunks_exact(2) {
            let high =
                hex_value(pair[0]).ok_or_else(|| IndexError::InvalidDigest(value.to_owned()))?;
            let low =
                hex_value(pair[1]).ok_or_else(|| IndexError::InvalidDigest(value.to_owned()))?;
            bytes.push((high << 4) | low);
        }
        Self::from_bytes(algorithm, bytes)
    }

    /// Computes a BLAKE3 digest.
    pub fn blake3(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        // A BLAKE3 hash is always exactly 32 bytes, so this cannot fail.
        Self::from_bytes(DigestAlgorithm::Blake3, hash.as_bytes()).expect("fixed BLAKE3 length")
    }

    /// Returns the algorithm tag.
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns lowercase hexadecimal bytes without the algorithm tag.
    pub fn hex(&self) -> String {
        let mut output = String::with_capacity(self.bytes.len() * 2);
        for byte in &self.bytes {
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 0x0f));
        }
        output
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("hex nibble is at most 15"),
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex())
    }
}

impl FromStr for Digest {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// The immutable artifact bytes referenced by a publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    size: u64,
    media_type: String,
    locations: Vec<MirrorUrl>,
    digests: Vec<Digest>,
}

impl ArtifactDescriptor {
    /// Creates an artifact descriptor with its original HTTPS locator.
    pub fn new(
        size: u64,
        media_type: impl Into<String>,
        locator: impl Into<String>,
        digest: Digest,
    ) -> IndexResult<Self> {
        let media_type = media_type.into();
        if media_type.is_empty()
            || !media_type.is_ascii()
            || media_type
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(IndexError::InvalidValue {
                kind: "artifact media type",
                value: media_type,
            });
        }
        let locator = MirrorUrl::new(locator)?;
        Ok(Self {
            size,
            media_type,
            locations: vec![locator.clone()],
            digests: vec![digest],
        })
    }

    /// Alias for [`ArtifactDescriptor::new`].
    pub fn new_with_locator(
        size: u64,
        media_type: impl Into<String>,
        locator: impl Into<String>,
        digest: Digest,
    ) -> IndexResult<Self> {
        Self::new(size, media_type, locator, digest)
    }

    /// Creates an artifact descriptor with one or more HTTPS locators.
    pub fn new_with_locations(
        size: u64,
        media_type: impl Into<String>,
        locations: Vec<MirrorUrl>,
        digest: Digest,
    ) -> IndexResult<Self> {
        let Some(locator) = locations.first().cloned() else {
            return Err(IndexError::Empty {
                kind: "artifact locations",
            });
        };
        let mut descriptor = Self::new(size, media_type, locator.to_string(), digest)?;
        let mut locations = locations;
        locations.sort();
        if locations.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IndexError::InvalidEvent("duplicate artifact location"));
        }
        descriptor.locations = locations;
        Ok(descriptor)
    }

    /// Creates an artifact descriptor with a digest set and locators.
    pub fn new_with_digest_set(
        size: u64,
        media_type: impl Into<String>,
        locations: Vec<MirrorUrl>,
        digests: Vec<Digest>,
    ) -> IndexResult<Self> {
        let mut digests = digests;
        digests.sort();
        let Some(primary) = digests.first().cloned() else {
            return Err(IndexError::Empty {
                kind: "artifact digests",
            });
        };
        if digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IndexError::InvalidEvent("duplicate artifact digest"));
        }
        let mut descriptor = Self::new_with_locations(size, media_type, locations, primary)?;
        descriptor.digests = digests;
        Ok(descriptor)
    }

    /// Artifact byte length.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Artifact media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Original artifact HTTPS locator.  The locator is transport only; the
    /// digest remains the artifact identity.
    pub fn locator(&self) -> &MirrorUrl {
        &self.locations[0]
    }

    /// All original artifact locators, in canonical order.
    pub fn locations(&self) -> &[MirrorUrl] {
        &self.locations
    }

    /// Primary artifact content digest (the first digest in canonical order).
    pub fn digest(&self) -> &Digest {
        &self.digests[0]
    }

    /// All artifact content digests, in canonical order.
    pub fn digests(&self) -> &[Digest] {
        &self.digests
    }
}

/// Publisher identity sealed into a publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    #[serde(rename = "identity")]
    actor: ActorId,
    signing_key: Digest,
}

impl PublisherIdentity {
    /// Creates a publisher identity from an actor and signing-key fingerprint.
    pub fn new(actor: ActorId, signing_key: Digest) -> Self {
        Self { actor, signing_key }
    }

    /// Publisher actor identity.
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// Signing-key fingerprint.
    pub fn signing_key(&self) -> &Digest {
        &self.signing_key
    }
}

/// A Git object identifier, restricted to a lowercase SHA-1 or SHA-256 form.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitObjectId(String);

impl GitObjectId {
    /// Creates a lowercase 40- or 64-character Git object identifier.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        if !((value.len() == 40) || (value.len() == 64))
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(IndexError::InvalidValue {
                kind: "Git object id",
                value,
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical object identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for GitObjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Stable source-repository and original-artifact provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProvenance {
    repository: MirrorUrl,
    github_owner_id: u64,
    github_repository_id: u64,
    commit: GitObjectId,
    tree: GitObjectId,
    release_ref: String,
    subdirectory: Option<String>,
    source_digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct SourceProvenanceWire {
    repository_url: MirrorUrl,
    github_owner_id: u64,
    github_repository_id: u64,
    commit: GitObjectId,
    tree: GitObjectId,
    tag: String,
    subdirectory: Option<String>,
    source_digest: Digest,
}

impl Serialize for SourceProvenance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SourceProvenanceWire {
            repository_url: self.repository.clone(),
            github_owner_id: self.github_owner_id,
            github_repository_id: self.github_repository_id,
            commit: self.commit.clone(),
            tree: self.tree.clone(),
            tag: self.release_ref.clone(),
            subdirectory: self.subdirectory.clone(),
            source_digest: self.source_digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SourceProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SourceProvenanceWire::deserialize(deserializer)?;
        Self::new(
            wire.repository_url,
            wire.github_owner_id,
            wire.github_repository_id,
            wire.commit,
            wire.tree,
            wire.tag,
            wire.subdirectory,
            wire.source_digest,
        )
        .map_err(de::Error::custom)
    }
}

impl SourceProvenance {
    /// Creates source provenance.  Repository and release references are
    /// immutable identity claims, not mutable download locators.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: MirrorUrl,
        github_owner_id: u64,
        github_repository_id: u64,
        commit: GitObjectId,
        tree: GitObjectId,
        release_ref: impl Into<String>,
        subdirectory: Option<String>,
        source_digest: Digest,
    ) -> IndexResult<Self> {
        let release_ref = release_ref.into();
        validate_reference_text(&release_ref, "release ref")?;
        if github_owner_id == 0 || github_repository_id == 0 {
            return Err(IndexError::InvalidEvent(
                "GitHub owner/repository IDs must be non-zero",
            ));
        }
        if release_ref.starts_with('.')
            || release_ref.contains('/')
            || release_ref.contains('\\')
            || release_ref.contains("..")
            || release_ref.chars().any(char::is_whitespace)
        {
            return Err(IndexError::InvalidValue {
                kind: "release ref",
                value: release_ref,
            });
        }
        if let Some(subdirectory) = &subdirectory {
            validate_subdirectory(subdirectory)?;
        }
        Ok(Self {
            repository,
            github_owner_id,
            github_repository_id,
            commit,
            tree,
            release_ref,
            subdirectory,
            source_digest,
        })
    }

    /// Source repository URL.
    pub fn repository(&self) -> &MirrorUrl {
        &self.repository
    }

    /// Numeric GitHub owner ID.
    pub const fn github_owner_id(&self) -> u64 {
        self.github_owner_id
    }

    /// Numeric GitHub repository ID.
    pub const fn github_repository_id(&self) -> u64 {
        self.github_repository_id
    }

    /// Source commit object ID.
    pub fn commit(&self) -> &GitObjectId {
        &self.commit
    }

    /// Source tree object ID.
    pub fn tree(&self) -> &GitObjectId {
        &self.tree
    }

    /// Release tag/ref.
    pub fn release_ref(&self) -> &str {
        &self.release_ref
    }

    /// Optional source subdirectory.
    pub fn subdirectory(&self) -> Option<&str> {
        self.subdirectory.as_deref()
    }

    /// Digest of the canonical source tree/provenance projection.
    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }
}

fn validate_reference_text(value: &str, kind: &'static str) -> IndexResult<()> {
    if value.is_empty() || value.chars().any(char::is_control) || value.contains('\0') {
        return Err(IndexError::InvalidValue {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_subdirectory(value: &str) -> IndexResult<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains('%')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.chars().any(char::is_control)
    {
        return Err(IndexError::InvalidValue {
            kind: "source subdirectory",
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Runtime and Component Model ABI requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRequirements {
    runtime: String,
    abi: String,
    digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct RuntimeRequirementsWire {
    runtime: String,
    abi: String,
    digest: Digest,
}

impl Serialize for RuntimeRequirements {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RuntimeRequirementsWire {
            runtime: self.runtime.clone(),
            abi: self.abi.clone(),
            digest: self.digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeRequirements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RuntimeRequirementsWire::deserialize(deserializer)?;
        Self::new_with_digest(wire.runtime, wire.abi, wire.digest).map_err(de::Error::custom)
    }
}

impl RuntimeRequirements {
    /// Creates runtime/ABI requirements.
    pub fn new(runtime: impl Into<String>, abi: impl Into<String>) -> IndexResult<Self> {
        let runtime = runtime.into();
        let abi = abi.into();
        validate_reference_text(&runtime, "runtime requirement")?;
        validate_reference_text(&abi, "ABI requirement")?;
        let mut projection = Vec::new();
        put_text(&mut projection, &runtime);
        put_text(&mut projection, &abi);
        Self::new_with_digest(runtime, abi, Digest::blake3(&projection))
    }

    /// Creates runtime/ABI requirements with their effective digest.
    pub fn new_with_digest(
        runtime: impl Into<String>,
        abi: impl Into<String>,
        digest: Digest,
    ) -> IndexResult<Self> {
        let runtime = runtime.into();
        let abi = abi.into();
        validate_reference_text(&runtime, "runtime requirement")?;
        validate_reference_text(&abi, "ABI requirement")?;
        Ok(Self {
            runtime,
            abi,
            digest,
        })
    }

    /// Runtime requirement string.
    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    /// ABI requirement string.
    pub fn abi(&self) -> &str {
        &self.abi
    }

    /// Digest of the effective runtime/ABI requirement projection.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// Embedded package identity asserted by the component itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EmbeddedPackageIdentity {
    coordinate: Coordinate,
    version: CanonicalSemVer,
    package_digest: Digest,
}

impl EmbeddedPackageIdentity {
    /// Creates an embedded package identity.
    pub fn new(coordinate: Coordinate, version: CanonicalSemVer, package_digest: Digest) -> Self {
        Self {
            coordinate,
            version,
            package_digest,
        }
    }

    /// Embedded package coordinate.
    pub fn coordinate(&self) -> &Coordinate {
        &self.coordinate
    }

    /// Embedded package version.
    pub fn version(&self) -> &CanonicalSemVer {
        &self.version
    }

    /// Digest of the embedded package identity.
    pub fn package_digest(&self) -> &Digest {
        &self.package_digest
    }
}

/// A dependency edge included in a publication's immutable graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencySpec {
    coordinate: Coordinate,
    requirement: String,
    optional: bool,
}

#[derive(Serialize, Deserialize)]
struct DependencySpecWire {
    coordinate: Coordinate,
    requirement: String,
    optional: bool,
}

impl Serialize for DependencySpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DependencySpecWire {
            coordinate: self.coordinate.clone(),
            requirement: self.requirement.clone(),
            optional: self.optional,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DependencySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DependencySpecWire::deserialize(deserializer)?;
        Self::new(wire.coordinate, wire.requirement, wire.optional).map_err(de::Error::custom)
    }
}

impl DependencySpec {
    /// Creates a dependency after checking its SemVer requirement.
    pub fn new(
        coordinate: Coordinate,
        requirement: impl Into<String>,
        optional: bool,
    ) -> IndexResult<Self> {
        let requirement = requirement.into();
        VersionReq::parse(&requirement).map_err(|error| IndexError::InvalidVersion {
            value: requirement.clone(),
            reason: error.to_string(),
        })?;
        Ok(Self {
            coordinate,
            requirement,
            optional,
        })
    }

    /// Dependency coordinate.
    pub fn coordinate(&self) -> &Coordinate {
        &self.coordinate
    }

    /// SemVer-compatible requirement.
    pub fn requirement(&self) -> &str {
        &self.requirement
    }

    /// Whether this dependency is optional.
    pub const fn optional(&self) -> bool {
        self.optional
    }
}

/// Requested capabilities and the effective IPC declaration digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityClaims {
    capabilities: Vec<String>,
    effective_ipc_digest: Digest,
    declaration_digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct CapabilityClaimsWire {
    capabilities: Vec<String>,
    effective_ipc_digest: Digest,
    declaration_digest: Digest,
}

impl Serialize for CapabilityClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CapabilityClaimsWire {
            capabilities: self.capabilities.clone(),
            effective_ipc_digest: self.effective_ipc_digest.clone(),
            declaration_digest: self.declaration_digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CapabilityClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CapabilityClaimsWire::deserialize(deserializer)?;
        Self::new_with_digests(
            wire.capabilities,
            wire.effective_ipc_digest,
            wire.declaration_digest,
        )
        .map_err(de::Error::custom)
    }
}

impl CapabilityClaims {
    /// Creates sorted, unique capability claims.
    pub fn new(capabilities: Vec<String>, effective_ipc_digest: Digest) -> IndexResult<Self> {
        let mut sorted = capabilities.clone();
        sorted.sort();
        let mut projection = Vec::new();
        for capability in &sorted {
            put_text(&mut projection, capability);
        }
        Self::new_with_digests(
            capabilities,
            effective_ipc_digest,
            Digest::blake3(&projection),
        )
    }

    /// Creates claims with separate capability and effective-IPC digests.
    pub fn new_with_digests(
        mut capabilities: Vec<String>,
        effective_ipc_digest: Digest,
        declaration_digest: Digest,
    ) -> IndexResult<Self> {
        if capabilities.iter().any(|value| {
            value.is_empty() || value.contains('\0') || value.chars().any(char::is_control)
        }) {
            return Err(IndexError::InvalidEvent("invalid capability claim"));
        }
        capabilities.sort();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IndexError::InvalidEvent("duplicate capability claim"));
        }
        Ok(Self {
            capabilities,
            effective_ipc_digest,
            declaration_digest,
        })
    }

    /// Sorted capability claims.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Digest of the effective IPC declaration.
    pub fn effective_ipc_digest(&self) -> &Digest {
        &self.effective_ipc_digest
    }

    /// Digest of the requested capability declaration.
    pub fn declaration_digest(&self) -> &Digest {
        &self.declaration_digest
    }
}

/// Dependency graph plus its canonical declaration digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyClaims {
    dependencies: Vec<DependencySpec>,
    digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct DependencyClaimsWire {
    dependencies: Vec<DependencySpec>,
    digest: Digest,
}

impl Serialize for DependencyClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DependencyClaimsWire {
            dependencies: self.dependencies.clone(),
            digest: self.digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DependencyClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DependencyClaimsWire::deserialize(deserializer)?;
        Self::new_with_digest(wire.dependencies, wire.digest).map_err(de::Error::custom)
    }
}

impl DependencyClaims {
    /// Creates a sorted, unique dependency graph.
    pub fn new(dependencies: Vec<DependencySpec>) -> IndexResult<Self> {
        let mut dependencies = dependencies;
        dependencies.sort_by(|left, right| {
            left.coordinate
                .cmp(&right.coordinate)
                .then_with(|| left.requirement.cmp(&right.requirement))
                .then_with(|| left.optional.cmp(&right.optional))
        });
        let mut projection = Vec::new();
        for dependency in &dependencies {
            put_text(&mut projection, &dependency.coordinate.to_string());
            put_text(&mut projection, &dependency.requirement);
            projection.push(u8::from(dependency.optional));
        }
        Self::new_with_digest(dependencies, Digest::blake3(&projection))
    }

    /// Creates a dependency graph with its effective declaration digest.
    pub fn new_with_digest(
        mut dependencies: Vec<DependencySpec>,
        digest: Digest,
    ) -> IndexResult<Self> {
        dependencies.sort_by(|left, right| {
            left.coordinate
                .cmp(&right.coordinate)
                .then_with(|| left.requirement.cmp(&right.requirement))
                .then_with(|| left.optional.cmp(&right.optional))
        });
        if dependencies.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IndexError::InvalidEvent("duplicate dependency"));
        }
        Ok(Self {
            dependencies,
            digest,
        })
    }

    /// Sorted dependency edges.
    pub fn dependencies(&self) -> &[DependencySpec] {
        &self.dependencies
    }

    /// Digest of the effective dependency declaration.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// Typed package projection sealed into a publication record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageClaims {
    embedded_identity: EmbeddedPackageIdentity,
    manifest_digest: Digest,
    component_digest: Digest,
    wit_digest: Digest,
    capabilities: CapabilityClaims,
    runtime: RuntimeRequirements,
    dependencies: DependencyClaims,
}

impl PackageClaims {
    /// Creates the complete package projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        embedded_identity: EmbeddedPackageIdentity,
        manifest_digest: Digest,
        component_digest: Digest,
        wit_digest: Digest,
        capabilities: CapabilityClaims,
        runtime: RuntimeRequirements,
        dependencies: DependencyClaims,
    ) -> Self {
        Self {
            embedded_identity,
            manifest_digest,
            component_digest,
            wit_digest,
            capabilities,
            runtime,
            dependencies,
        }
    }

    /// Embedded package identity.
    pub fn embedded_identity(&self) -> &EmbeddedPackageIdentity {
        &self.embedded_identity
    }

    /// Manifest digest.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    /// Component digest.
    pub fn component_digest(&self) -> &Digest {
        &self.component_digest
    }

    /// WIT digest.
    pub fn wit_digest(&self) -> &Digest {
        &self.wit_digest
    }

    /// Capability claims.
    pub fn capabilities(&self) -> &CapabilityClaims {
        &self.capabilities
    }

    /// Runtime/ABI requirements.
    pub fn runtime(&self) -> &RuntimeRequirements {
        &self.runtime
    }

    /// Dependency claims.
    pub fn dependencies(&self) -> &DependencyClaims {
        &self.dependencies
    }
}

/// Build-provenance and attestation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildProvenance {
    predicate_type: String,
    statement_digest: Digest,
    builder: MirrorUrl,
    attestation_identity: String,
}

#[derive(Serialize, Deserialize)]
struct BuildProvenanceWire {
    predicate_type: String,
    statement_digest: Digest,
    builder_identity: MirrorUrl,
    attestation_identity: String,
}

impl Serialize for BuildProvenance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BuildProvenanceWire {
            predicate_type: self.predicate_type.clone(),
            statement_digest: self.statement_digest.clone(),
            builder_identity: self.builder.clone(),
            attestation_identity: self.attestation_identity.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BuildProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BuildProvenanceWire::deserialize(deserializer)?;
        Self::new(
            wire.predicate_type,
            wire.statement_digest,
            wire.builder_identity,
            wire.attestation_identity,
        )
        .map_err(de::Error::custom)
    }
}

impl BuildProvenance {
    /// Creates typed build provenance.
    pub fn new(
        predicate_type: impl Into<String>,
        statement_digest: Digest,
        builder: MirrorUrl,
        attestation_identity: impl Into<String>,
    ) -> IndexResult<Self> {
        let predicate_type = predicate_type.into();
        let attestation_identity = attestation_identity.into();
        validate_reference_text(&predicate_type, "provenance predicate")?;
        validate_reference_text(&attestation_identity, "attestation identity")?;
        Ok(Self {
            predicate_type,
            statement_digest,
            builder,
            attestation_identity,
        })
    }

    /// Predicate type URL/string.
    pub fn predicate_type(&self) -> &str {
        &self.predicate_type
    }

    /// Provenance statement digest.
    pub fn statement_digest(&self) -> &Digest {
        &self.statement_digest
    }

    /// Builder URL.
    pub fn builder(&self) -> &MirrorUrl {
        &self.builder
    }

    /// Attestation identity.
    pub fn attestation_identity(&self) -> &str {
        &self.attestation_identity
    }
}

/// The immutable fields from which a publication is sealed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRecordInput {
    /// Schema identifier.
    pub schema: SchemaVersion,
    /// Index identity embedded in the record.
    pub index_id: IndexId,
    /// Capsule coordinate.
    pub coordinate: Coordinate,
    /// Canonical release version.
    pub version: CanonicalSemVer,
    /// Artifact bytes descriptor.
    pub artifact: ArtifactDescriptor,
    /// Deterministic metadata attached to the release.
    pub metadata: BTreeMap<String, String>,
    /// Publisher identity and signing-key fingerprint.
    pub publisher: PublisherIdentity,
    /// Stable source repository provenance.
    pub source: SourceProvenance,
    /// Complete typed package projection.
    pub package: PackageClaims,
    /// Build provenance and attestation identity.
    pub provenance: BuildProvenance,
}

impl PublicationRecordInput {
    /// Creates a complete publication input.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: SchemaVersion,
        index_id: IndexId,
        coordinate: Coordinate,
        version: CanonicalSemVer,
        artifact: ArtifactDescriptor,
        metadata: BTreeMap<String, String>,
        publisher: PublisherIdentity,
        source: SourceProvenance,
        package: PackageClaims,
        provenance: BuildProvenance,
    ) -> Self {
        Self {
            schema,
            index_id,
            coordinate,
            version,
            artifact,
            metadata,
            publisher,
            source,
            package,
            provenance,
        }
    }
}

/// Builder for a sealed publication record.
#[derive(Clone, Debug)]
pub struct PublicationRecordBuilder {
    schema: SchemaVersion,
    index_id: IndexId,
    coordinate: Coordinate,
    version: CanonicalSemVer,
    artifact: Option<ArtifactDescriptor>,
    metadata: BTreeMap<String, String>,
    publisher: Option<PublisherIdentity>,
    source: Option<SourceProvenance>,
    runtime: Option<RuntimeRequirements>,
    package_identity: Option<EmbeddedPackageIdentity>,
    manifest_digest: Option<Digest>,
    component_digest: Option<Digest>,
    wit_digest: Option<Digest>,
    capabilities: Option<CapabilityClaims>,
    dependencies: Option<DependencyClaims>,
    provenance: Option<BuildProvenance>,
    capability_digest_override: Option<Digest>,
    dependency_digest_override: Option<Digest>,
    provenance_digest_override: Option<Digest>,
    source_digest_override: Option<Digest>,
}

impl PublicationRecordBuilder {
    /// Starts a publication with the stable identity and coordinate.
    pub fn new(index_id: IndexId, coordinate: Coordinate, version: CanonicalSemVer) -> Self {
        Self {
            schema: SchemaVersion::v1(),
            index_id,
            coordinate,
            version,
            artifact: None,
            metadata: BTreeMap::new(),
            publisher: None,
            source: None,
            runtime: None,
            package_identity: None,
            manifest_digest: None,
            component_digest: None,
            wit_digest: None,
            capabilities: None,
            dependencies: None,
            provenance: None,
            capability_digest_override: None,
            dependency_digest_override: None,
            provenance_digest_override: None,
            source_digest_override: None,
        }
    }

    /// Sets the schema identifier.
    pub fn schema(mut self, schema: SchemaVersion) -> Self {
        self.schema = schema;
        self
    }

    /// Sets the artifact descriptor.
    pub fn artifact(mut self, artifact: ArtifactDescriptor) -> Self {
        self.artifact = Some(artifact);
        self
    }

    /// Sets artifact size, media type, original locator, and digest together.
    pub fn artifact_fields(
        mut self,
        size: u64,
        media_type: impl Into<String>,
        locator: impl Into<String>,
        digest: Digest,
    ) -> IndexResult<Self> {
        self.artifact = Some(ArtifactDescriptor::new(size, media_type, locator, digest)?);
        Ok(self)
    }

    /// Sets artifact size, media type, locators, and digest together.
    pub fn artifact_locations(
        mut self,
        size: u64,
        media_type: impl Into<String>,
        locations: Vec<MirrorUrl>,
        digest: Digest,
    ) -> IndexResult<Self> {
        self.artifact = Some(ArtifactDescriptor::new_with_locations(
            size, media_type, locations, digest,
        )?);
        Ok(self)
    }

    /// Sets publisher identity.
    pub fn publisher(mut self, publisher: PublisherIdentity) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Sets source provenance.
    pub fn source(mut self, source: SourceProvenance) -> Self {
        self.source = Some(source);
        self
    }

    /// Sets runtime and ABI requirements.
    pub fn runtime(mut self, runtime: RuntimeRequirements) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Sets embedded package identity.
    pub fn package(mut self, package: EmbeddedPackageIdentity) -> Self {
        self.package_identity = Some(package);
        self
    }

    /// Sets capability claims.
    pub fn capabilities(mut self, capabilities: CapabilityClaims) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Sets dependency claims.
    pub fn dependencies(mut self, dependencies: DependencyClaims) -> Self {
        self.dependencies = Some(dependencies);
        self
    }

    /// Sets build provenance.
    pub fn provenance(mut self, provenance: BuildProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Sets the manifest digest.
    pub fn manifest_digest(mut self, digest: Digest) -> Self {
        self.manifest_digest = Some(digest);
        self
    }

    /// Sets the Component Model digest.
    pub fn component_digest(mut self, digest: Digest) -> Self {
        self.component_digest = Some(digest);
        self
    }

    /// Sets the WIT digest.
    pub fn wit_digest(mut self, digest: Digest) -> Self {
        self.wit_digest = Some(digest);
        self
    }

    /// Sets the capability declaration digest.
    pub fn capability_digest(mut self, digest: Digest) -> Self {
        self.capability_digest_override = Some(digest);
        self
    }

    /// Sets the dependency declaration digest.
    pub fn dependency_digest(mut self, digest: Digest) -> Self {
        self.dependency_digest_override = Some(digest);
        self
    }

    /// Sets the provenance digest.
    pub fn provenance_digest(mut self, digest: Digest) -> Self {
        self.provenance_digest_override = Some(digest);
        self
    }

    /// Sets the source digest.
    pub fn source_digest(mut self, digest: Digest) -> Self {
        self.source_digest_override = Some(digest);
        self
    }

    /// Replaces metadata.
    pub fn metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Adds one metadata key/value pair.
    pub fn insert_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Seals the immutable record.
    pub fn seal(self) -> IndexResult<PublicationRecord> {
        let package_identity = self
            .package_identity
            .ok_or(IndexError::MissingField("package embedded identity"))?;
        if package_identity.coordinate() != &self.coordinate
            || package_identity.version() != &self.version
        {
            return Err(IndexError::InvalidEvent(
                "embedded package identity does not match publication",
            ));
        }
        let capabilities = self
            .capabilities
            .ok_or(IndexError::MissingField("capabilities"))?;
        if let Some(expected) = &self.capability_digest_override
            && expected != capabilities.declaration_digest()
        {
            return Err(IndexError::InvalidEvent("capability digest mismatch"));
        }
        let dependencies = self
            .dependencies
            .ok_or(IndexError::MissingField("dependencies"))?;
        if let Some(expected) = &self.dependency_digest_override
            && expected != dependencies.digest()
        {
            return Err(IndexError::InvalidEvent("dependency digest mismatch"));
        }
        let provenance = self
            .provenance
            .ok_or(IndexError::MissingField("provenance"))?;
        if let Some(expected) = &self.provenance_digest_override
            && expected != provenance.statement_digest()
        {
            return Err(IndexError::InvalidEvent("provenance digest mismatch"));
        }
        let source = self
            .source
            .ok_or(IndexError::MissingField("source provenance"))?;
        if let Some(expected) = &self.source_digest_override
            && expected != source.source_digest()
        {
            return Err(IndexError::InvalidEvent("source digest mismatch"));
        }
        let runtime = self
            .runtime
            .ok_or(IndexError::MissingField("runtime requirements"))?;
        let publisher = self
            .publisher
            .ok_or(IndexError::MissingField("publisher"))?;
        let artifact = self.artifact.ok_or(IndexError::MissingField("artifact"))?;
        let package = PackageClaims::new(
            package_identity,
            self.manifest_digest
                .ok_or(IndexError::MissingField("manifest digest"))?,
            self.component_digest
                .ok_or(IndexError::MissingField("component digest"))?,
            self.wit_digest
                .ok_or(IndexError::MissingField("WIT digest"))?,
            capabilities,
            runtime,
            dependencies,
        );
        PublicationRecord::seal(PublicationRecordInput {
            schema: self.schema,
            index_id: self.index_id,
            coordinate: self.coordinate,
            version: self.version,
            artifact,
            metadata: self.metadata,
            publisher,
            source,
            package,
            provenance,
        })
    }
}

/// Schema identifier for publication records.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaVersion(String);

impl SchemaVersion {
    /// Creates a schema identifier.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        validate_ascii_token(&value, "schema version")?;
        Ok(Self(value))
    }

    /// The initial publication schema.
    pub fn v1() -> Self {
        Self(PUBLICATION_SCHEMA_V1.to_owned())
    }

    /// The initial append-only event-envelope schema.
    pub fn event_v1() -> Self {
        Self(EVENT_SCHEMA_V1.to_owned())
    }

    /// Returns the schema string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SchemaVersion {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// The immutable key occupied by one publication.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PublicationKey {
    /// Stable index identifier.
    pub index_id: IndexId,
    /// Capsule coordinate.
    pub coordinate: Coordinate,
    /// Canonical release version.
    pub version: CanonicalSemVer,
}

impl PublicationKey {
    /// Creates a publication key.
    pub fn new(index_id: IndexId, coordinate: Coordinate, version: CanonicalSemVer) -> Self {
        Self {
            index_id,
            coordinate,
            version,
        }
    }
}

impl fmt::Display for PublicationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}@{}", self.index_id, self.coordinate, self.version)
    }
}

/// A sealed immutable publication record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRecord {
    schema: SchemaVersion,
    index_id: IndexId,
    coordinate: Coordinate,
    version: CanonicalSemVer,
    artifact: ArtifactDescriptor,
    metadata: BTreeMap<String, String>,
    publisher: PublisherIdentity,
    source: SourceProvenance,
    package: PackageClaims,
    provenance: BuildProvenance,
    publication_digest: Digest,
}

impl PublicationRecord {
    /// Seals an input and computes its domain-separated BLAKE3 identity.
    pub fn seal(input: PublicationRecordInput) -> IndexResult<Self> {
        if input.schema.as_str() != PUBLICATION_SCHEMA_V1 {
            return Err(IndexError::InvalidEvent("unsupported publication schema"));
        }
        if input
            .metadata
            .keys()
            .any(|key| key.is_empty() || key.contains('\0'))
            || input.metadata.values().any(|value| value.contains('\0'))
        {
            return Err(IndexError::InvalidEvent(
                "metadata contains an empty key or NUL",
            ));
        }
        // Re-validate the artifact media type even when an input was assembled
        // by a struct literal inside this crate.
        if input.artifact.locations.is_empty() {
            return Err(IndexError::MissingField("artifact locations"));
        }
        let artifact = ArtifactDescriptor::new_with_digest_set(
            input.artifact.size,
            input.artifact.media_type.clone(),
            input.artifact.locations.clone(),
            input.artifact.digests.clone(),
        )?;
        if input.package.embedded_identity.coordinate() != &input.coordinate
            || input.package.embedded_identity.version() != &input.version
        {
            return Err(IndexError::InvalidEvent(
                "embedded package identity does not match publication",
            ));
        }
        let mut record = Self {
            schema: input.schema,
            index_id: input.index_id,
            coordinate: input.coordinate,
            version: input.version,
            artifact,
            metadata: input.metadata,
            publisher: input.publisher,
            source: input.source,
            package: input.package,
            provenance: input.provenance,
            publication_digest: Digest::blake3(&[0; 32]),
        };
        let mut digest_input =
            Vec::with_capacity(PUBLICATION_DOMAIN.len() + record.canonical_bytes().len());
        digest_input.extend_from_slice(PUBLICATION_DOMAIN);
        digest_input.extend_from_slice(&record.canonical_bytes());
        record.publication_digest = Digest::blake3(&digest_input);
        Ok(record)
    }

    /// Starts a builder for a sealed publication.
    pub fn builder(
        index_id: IndexId,
        coordinate: Coordinate,
        version: CanonicalSemVer,
    ) -> PublicationRecordBuilder {
        PublicationRecordBuilder::new(index_id, coordinate, version)
    }

    /// Stable publication key.
    pub fn key(&self) -> PublicationKey {
        PublicationKey::new(
            self.index_id.clone(),
            self.coordinate.clone(),
            self.version.clone(),
        )
    }

    /// Record schema.
    pub fn schema(&self) -> &SchemaVersion {
        &self.schema
    }

    /// Index identifier embedded in this record.
    pub fn index_id(&self) -> &IndexId {
        &self.index_id
    }

    /// Capsule coordinate.
    pub fn coordinate(&self) -> &Coordinate {
        &self.coordinate
    }

    /// Canonical release version.
    pub fn version(&self) -> &CanonicalSemVer {
        &self.version
    }

    /// Artifact descriptor.
    pub fn artifact(&self) -> &ArtifactDescriptor {
        &self.artifact
    }

    /// Manifest digest.
    pub fn manifest_digest(&self) -> &Digest {
        self.package.manifest_digest()
    }

    /// Component digest.
    pub fn component_digest(&self) -> &Digest {
        self.package.component_digest()
    }

    /// WIT digest.
    pub fn wit_digest(&self) -> &Digest {
        self.package.wit_digest()
    }

    /// Capability digest.
    pub fn capability_digest(&self) -> &Digest {
        self.package.capabilities().declaration_digest()
    }

    /// Dependency digest.
    pub fn dependency_digest(&self) -> &Digest {
        self.package.dependencies().digest()
    }

    /// Provenance digest.
    pub fn provenance_digest(&self) -> &Digest {
        self.provenance.statement_digest()
    }

    /// Source digest.
    pub fn source_digest(&self) -> &Digest {
        self.source.source_digest()
    }

    /// Metadata, sorted by key for deterministic serialization.
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// Publisher identity.
    pub fn publisher(&self) -> &PublisherIdentity {
        &self.publisher
    }

    /// Source repository provenance.
    pub fn source(&self) -> &SourceProvenance {
        &self.source
    }

    /// Runtime and ABI requirements.
    pub fn runtime(&self) -> &RuntimeRequirements {
        self.package.runtime()
    }

    /// Embedded package identity.
    pub fn package(&self) -> &PackageClaims {
        &self.package
    }

    /// Embedded package identity.
    pub fn embedded_package(&self) -> &EmbeddedPackageIdentity {
        self.package.embedded_identity()
    }

    /// Capability claims.
    pub fn capabilities(&self) -> &CapabilityClaims {
        self.package.capabilities()
    }

    /// Dependency claims.
    pub fn dependencies(&self) -> &DependencyClaims {
        self.package.dependencies()
    }

    /// Build provenance and attestation identity.
    pub fn provenance(&self) -> &BuildProvenance {
        &self.provenance
    }

    /// Domain-separated BLAKE3 digest of the immutable fields.
    pub fn publication_digest(&self) -> &Digest {
        &self.publication_digest
    }

    /// Canonical bytes of the immutable fields, without the domain prefix.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_text(&mut bytes, self.schema.as_str());
        put_text(&mut bytes, self.index_id.as_str());
        put_text(&mut bytes, self.coordinate.namespace.as_str());
        put_text(&mut bytes, self.coordinate.name.as_str());
        put_text(&mut bytes, &self.version.to_string());
        put_u64(&mut bytes, self.artifact.size);
        put_text(&mut bytes, &self.artifact.media_type);
        put_u64(&mut bytes, self.artifact.locations.len() as u64);
        for location in &self.artifact.locations {
            put_text(&mut bytes, location.as_str());
        }
        // Preserve the complete digest set in canonical order.  The primary
        // digest is the first member of this set, but it is not sufficient to
        // identify a record by itself: adding/removing an alternate digest is
        // an immutable artifact mutation and must change the publication
        // digest.
        put_u64(&mut bytes, self.artifact.digests.len() as u64);
        for digest in &self.artifact.digests {
            put_digest(&mut bytes, digest);
        }
        put_text(&mut bytes, self.publisher.actor.as_str());
        put_digest(&mut bytes, &self.publisher.signing_key);
        put_text(&mut bytes, self.source.repository.as_str());
        put_u64(&mut bytes, self.source.github_owner_id);
        put_u64(&mut bytes, self.source.github_repository_id);
        put_text(&mut bytes, self.source.commit.as_str());
        put_text(&mut bytes, self.source.tree.as_str());
        put_text(&mut bytes, &self.source.release_ref);
        put_optional_text(&mut bytes, self.source.subdirectory.as_deref());
        put_digest(&mut bytes, &self.source.source_digest);
        put_text(&mut bytes, &self.package.runtime.runtime);
        put_text(&mut bytes, &self.package.runtime.abi);
        put_digest(&mut bytes, &self.package.runtime.digest);
        put_text(
            &mut bytes,
            self.package.embedded_identity.coordinate.namespace.as_str(),
        );
        put_text(
            &mut bytes,
            self.package.embedded_identity.coordinate.name.as_str(),
        );
        put_text(
            &mut bytes,
            &self.package.embedded_identity.version.to_string(),
        );
        put_digest(&mut bytes, &self.package.embedded_identity.package_digest);
        put_digest(&mut bytes, self.package.manifest_digest());
        put_digest(&mut bytes, self.package.component_digest());
        put_digest(&mut bytes, self.package.wit_digest());
        put_u64(
            &mut bytes,
            self.package.capabilities.capabilities.len() as u64,
        );
        for capability in &self.package.capabilities.capabilities {
            put_text(&mut bytes, capability);
        }
        put_digest(&mut bytes, &self.package.capabilities.declaration_digest);
        put_digest(&mut bytes, &self.package.capabilities.effective_ipc_digest);
        put_text(&mut bytes, &self.package.runtime.runtime);
        put_text(&mut bytes, &self.package.runtime.abi);
        put_digest(&mut bytes, &self.package.runtime.digest);
        put_u64(
            &mut bytes,
            self.package.dependencies.dependencies.len() as u64,
        );
        for dependency in &self.package.dependencies.dependencies {
            put_text(&mut bytes, &dependency.coordinate.namespace.to_string());
            put_text(&mut bytes, &dependency.coordinate.name.to_string());
            put_text(&mut bytes, &dependency.requirement);
            bytes.push(u8::from(dependency.optional));
        }
        put_digest(&mut bytes, &self.package.dependencies.digest);
        put_text(&mut bytes, &self.provenance.predicate_type);
        put_digest(&mut bytes, &self.provenance.statement_digest);
        put_text(&mut bytes, self.provenance.builder.as_str());
        put_text(&mut bytes, &self.provenance.attestation_identity);
        put_u64(&mut bytes, self.metadata.len() as u64);
        for (key, value) in &self.metadata {
            put_text(&mut bytes, key);
            put_text(&mut bytes, value);
        }
        bytes
    }

    /// Alias for [`PublicationRecord::canonical_bytes`].
    pub fn canonical_serialization(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    /// Compares this record with an existing same-key record.
    pub fn classify_against(&self, existing: Option<&Self>) -> PublicationClassification {
        match existing {
            None => PublicationClassification::New,
            Some(existing)
                if existing.key() == self.key()
                    && existing.publication_digest == self.publication_digest =>
            {
                PublicationClassification::Idempotent
            },
            Some(_) => PublicationClassification::Equivocation,
        }
    }
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_text(bytes: &mut Vec<u8>, value: &str) {
    put_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn put_optional_text(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            put_text(bytes, value);
        },
        None => bytes.push(0),
    }
}

fn put_digest(bytes: &mut Vec<u8>, digest: &Digest) {
    put_text(bytes, digest.algorithm.as_str());
    put_u64(bytes, digest.bytes.len() as u64);
    bytes.extend_from_slice(&digest.bytes);
}

/// Classification of a candidate against an occupied publication key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationClassification {
    /// No record currently occupies the key.
    New,
    /// The candidate has exactly the same immutable digest.
    Idempotent,
    /// The candidate changes immutable bytes under the same key.
    Equivocation,
}

#[derive(Serialize, Deserialize)]
struct PublicationWire {
    schema: SchemaVersion,
    index_id: IndexId,
    coordinate: Coordinate,
    version: CanonicalSemVer,
    artifact: ArtifactWire,
    package: PackageWire,
    publisher: PublisherWire,
    source: SourceWire,
    provenance: ProvenanceWire,
    metadata: BTreeMap<String, String>,
    publication_digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct ArtifactWire {
    digests: Vec<Digest>,
    size: u64,
    media_type: String,
    locations: Vec<MirrorUrl>,
}

#[derive(Serialize, Deserialize)]
struct PackageWire {
    embedded_identity: EmbeddedPackageIdentity,
    manifest_digest: Digest,
    component_digest: Digest,
    wit_digest: Digest,
    capability_digest: Digest,
    ipc_digest: Digest,
    runtime_abi_digest: Digest,
    dependency_digest: Digest,
    capabilities: Vec<String>,
    dependencies: Vec<DependencySpec>,
    runtime: RuntimeRequirements,
}

#[derive(Serialize, Deserialize)]
struct PublisherWire {
    identity: ActorId,
    signing_key: Digest,
}

#[derive(Serialize, Deserialize)]
struct SourceWire {
    repository_url: MirrorUrl,
    github_owner_id: u64,
    github_repository_id: u64,
    commit: GitObjectId,
    tree: GitObjectId,
    tag: String,
    subdirectory: Option<String>,
    source_digest: Digest,
}

#[derive(Serialize, Deserialize)]
struct ProvenanceWire {
    predicate_type: String,
    statement_digest: Digest,
    builder_identity: MirrorUrl,
    attestation_identity: String,
}

impl Serialize for PublicationRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PublicationWire {
            schema: self.schema.clone(),
            index_id: self.index_id.clone(),
            coordinate: self.coordinate.clone(),
            version: self.version.clone(),
            artifact: ArtifactWire {
                digests: self.artifact.digests.clone(),
                size: self.artifact.size,
                media_type: self.artifact.media_type.clone(),
                locations: self.artifact.locations.clone(),
            },
            package: PackageWire {
                embedded_identity: self.package.embedded_identity.clone(),
                manifest_digest: self.package.manifest_digest.clone(),
                component_digest: self.package.component_digest.clone(),
                wit_digest: self.package.wit_digest.clone(),
                capability_digest: self.package.capabilities.declaration_digest.clone(),
                ipc_digest: self.package.capabilities.effective_ipc_digest.clone(),
                runtime_abi_digest: self.package.runtime.digest.clone(),
                dependency_digest: self.package.dependencies.digest.clone(),
                capabilities: self.package.capabilities.capabilities.clone(),
                dependencies: self.package.dependencies.dependencies.clone(),
                runtime: self.package.runtime.clone(),
            },
            publisher: PublisherWire {
                identity: self.publisher.actor.clone(),
                signing_key: self.publisher.signing_key.clone(),
            },
            source: SourceWire {
                repository_url: self.source.repository.clone(),
                github_owner_id: self.source.github_owner_id,
                github_repository_id: self.source.github_repository_id,
                commit: self.source.commit.clone(),
                tree: self.source.tree.clone(),
                tag: self.source.release_ref.clone(),
                subdirectory: self.source.subdirectory.clone(),
                source_digest: self.source.source_digest.clone(),
            },
            provenance: ProvenanceWire {
                predicate_type: self.provenance.predicate_type.clone(),
                statement_digest: self.provenance.statement_digest.clone(),
                builder_identity: self.provenance.builder.clone(),
                attestation_identity: self.provenance.attestation_identity.clone(),
            },
            metadata: self.metadata.clone(),
            publication_digest: self.publication_digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicationRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PublicationWire::deserialize(deserializer)?;
        let expected = wire.publication_digest.clone();
        let artifact = ArtifactDescriptor::new_with_digest_set(
            wire.artifact.size,
            wire.artifact.media_type,
            wire.artifact.locations,
            wire.artifact.digests,
        )
        .map_err(de::Error::custom)?;
        let package_caps = CapabilityClaims::new_with_digests(
            wire.package.capabilities,
            wire.package.ipc_digest,
            wire.package.capability_digest,
        )
        .map_err(de::Error::custom)?;
        let package_deps = DependencyClaims::new_with_digest(
            wire.package.dependencies,
            wire.package.dependency_digest,
        )
        .map_err(de::Error::custom)?;
        let package = PackageClaims::new(
            wire.package.embedded_identity,
            wire.package.manifest_digest,
            wire.package.component_digest,
            wire.package.wit_digest,
            package_caps,
            wire.package.runtime,
            package_deps,
        );
        let record = Self::seal(PublicationRecordInput {
            schema: wire.schema,
            index_id: wire.index_id,
            coordinate: wire.coordinate,
            version: wire.version,
            artifact,
            metadata: wire.metadata,
            publisher: PublisherIdentity::new(wire.publisher.identity, wire.publisher.signing_key),
            source: SourceProvenance::new(
                wire.source.repository_url,
                wire.source.github_owner_id,
                wire.source.github_repository_id,
                wire.source.commit,
                wire.source.tree,
                wire.source.tag,
                wire.source.subdirectory,
                wire.source.source_digest,
            )
            .map_err(de::Error::custom)?,
            package,
            provenance: BuildProvenance::new(
                wire.provenance.predicate_type,
                wire.provenance.statement_digest,
                wire.provenance.builder_identity,
                wire.provenance.attestation_identity,
            )
            .map_err(de::Error::custom)?,
        })
        .map_err(de::Error::custom)?;
        if record.publication_digest != expected {
            return Err(de::Error::custom(IndexError::PublicationDigestMismatch));
        }
        Ok(record)
    }
}

/// Actor identity recorded on every authorization-relevant event.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActorId(String);

impl ActorId {
    /// Creates a non-empty actor identity without normalizing case or Unicode.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(IndexError::InvalidValue {
                kind: "actor id",
                value,
            });
        }
        Ok(Self(value))
    }

    /// Returns the actor identity exactly as recorded.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActorId {
    type Err = IndexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ActorId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ActorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Authorization evidence attached to an event or ownership transfer.
///
/// The domain crate validates presence and binding of the evidence, but does
/// not verify cryptographic signatures.  An index/TUF implementation supplies
/// an [`EventAuthorizationVerifier`] for that policy decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventAuthorization {
    actor: ActorId,
    evidence: String,
    signature_digest: Digest,
}

impl EventAuthorization {
    /// Creates non-empty authorization evidence for an actor.
    pub fn new(
        actor: ActorId,
        evidence: impl Into<String>,
        signature_digest: Digest,
    ) -> IndexResult<Self> {
        let evidence = evidence.into();
        validate_reference_text(&evidence, "authorization evidence")?;
        Ok(Self {
            actor,
            evidence,
            signature_digest,
        })
    }

    /// Actor represented by the evidence.
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// Stable evidence reference (for example a key/attestation identity).
    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    /// Digest of the detached signature/evidence bytes.
    pub fn signature_digest(&self) -> &Digest {
        &self.signature_digest
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_text(&mut bytes, self.actor.as_str());
        put_text(&mut bytes, &self.evidence);
        put_digest(&mut bytes, &self.signature_digest);
        bytes
    }
}

#[derive(Serialize, Deserialize)]
struct EventAuthorizationWire {
    actor: ActorId,
    evidence: String,
    signature_digest: Digest,
}

impl Serialize for EventAuthorization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EventAuthorizationWire {
            actor: self.actor.clone(),
            evidence: self.evidence.clone(),
            signature_digest: self.signature_digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EventAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EventAuthorizationWire::deserialize(deserializer)?;
        Self::new(wire.actor, wire.evidence, wire.signature_digest).map_err(de::Error::custom)
    }
}

/// Compatibility alias for callers that use the shorter evidence name.
pub type AuthorizationEvidence = EventAuthorization;

/// Hook supplied by an index/TUF implementation to verify detached event
/// authorization.  This crate intentionally performs no signature crypto.
pub trait EventAuthorizationVerifier {
    /// Verifies the authorization evidence for an already structurally valid
    /// envelope.
    fn verify(&self, envelope: &EventEnvelope) -> IndexResult<()>;
}

/// Immutable namespace ownership and source claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceClaim {
    namespace: Namespace,
    owner: ActorId,
    security_contact: String,
    repository: MirrorUrl,
    github_owner_id: u64,
    github_repository_id: u64,
    signing_identity: ActorId,
    license: String,
    reserved_authority: Option<IndexId>,
}

impl NamespaceClaim {
    /// Creates a namespace claim.  Reserved namespaces must carry the matching
    /// authority marker (`astrid` or `aos`); the marker is checked again when a
    /// claim is registered against a concrete index identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: Namespace,
        owner: ActorId,
        security_contact: impl Into<String>,
        repository: MirrorUrl,
        github_owner_id: u64,
        github_repository_id: u64,
        signing_identity: ActorId,
        license: impl Into<String>,
        reserved_authority: Option<IndexId>,
    ) -> IndexResult<Self> {
        let security_contact = security_contact.into();
        let license = license.into();
        validate_reference_text(&security_contact, "security contact")?;
        validate_reference_text(&license, "license")?;
        if github_owner_id == 0 || github_repository_id == 0 {
            return Err(IndexError::InvalidEvent(
                "GitHub owner/repository IDs must be non-zero",
            ));
        }
        let claim = Self {
            namespace,
            owner,
            security_contact,
            repository,
            github_owner_id,
            github_repository_id,
            signing_identity,
            license,
            reserved_authority,
        };
        claim.validate_reserved_marker()?;
        Ok(claim)
    }

    fn validate_reserved_marker(&self) -> IndexResult<()> {
        let reserved = match self.namespace.as_str() {
            "astrid" => Some("astrid"),
            "aos" => Some("aos"),
            _ => None,
        };
        match (reserved, self.reserved_authority.as_ref()) {
            (Some(expected), Some(authority)) if authority.as_str() == expected => Ok(()),
            (Some(_), _) => Err(IndexError::InvalidEvent(
                "reserved namespace requires its authority marker",
            )),
            (None, Some(_)) => Err(IndexError::InvalidEvent(
                "authority marker is only valid for a reserved namespace",
            )),
            (None, None) => Ok(()),
        }
    }

    /// Validates that the claim is admitted by one concrete index authority.
    pub fn validate_for_index(&self, index_id: &IndexId) -> IndexResult<()> {
        self.validate_reserved_marker()?;
        if let Some(authority) = &self.reserved_authority
            && authority != index_id
        {
            return Err(IndexError::WrongIndex {
                event: authority.clone(),
                expected: index_id.clone(),
            });
        }
        Ok(())
    }

    /// Claimed namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Stable current owner at claim creation.
    pub fn owner(&self) -> &ActorId {
        &self.owner
    }

    /// Security contact reference.
    pub fn security_contact(&self) -> &str {
        &self.security_contact
    }

    /// Source repository URL.
    pub fn repository(&self) -> &MirrorUrl {
        &self.repository
    }

    /// Numeric GitHub owner ID.
    pub const fn github_owner_id(&self) -> u64 {
        self.github_owner_id
    }

    /// Numeric GitHub repository ID.
    pub const fn github_repository_id(&self) -> u64 {
        self.github_repository_id
    }

    /// Signing identity reference.
    pub fn signing_identity(&self) -> &ActorId {
        &self.signing_identity
    }

    /// SPDX/license identity.
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Reserved authority marker, if this is a reserved namespace.
    pub fn reserved_authority(&self) -> Option<&IndexId> {
        self.reserved_authority.as_ref()
    }

    /// Canonical bytes for the immutable claim fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_text(&mut bytes, self.namespace.as_str());
        put_text(&mut bytes, self.owner.as_str());
        put_text(&mut bytes, &self.security_contact);
        put_text(&mut bytes, self.repository.as_str());
        put_u64(&mut bytes, self.github_owner_id);
        put_u64(&mut bytes, self.github_repository_id);
        put_text(&mut bytes, self.signing_identity.as_str());
        put_text(&mut bytes, &self.license);
        put_optional_text(
            &mut bytes,
            self.reserved_authority.as_ref().map(IndexId::as_str),
        );
        bytes
    }
}

#[derive(Serialize, Deserialize)]
struct NamespaceClaimWire {
    namespace: Namespace,
    owner: ActorId,
    security_contact: String,
    repository_url: MirrorUrl,
    github_owner_id: u64,
    github_repository_id: u64,
    signing_identity: ActorId,
    license: String,
    reserved_authority: Option<IndexId>,
}

impl Serialize for NamespaceClaim {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NamespaceClaimWire {
            namespace: self.namespace.clone(),
            owner: self.owner.clone(),
            security_contact: self.security_contact.clone(),
            repository_url: self.repository.clone(),
            github_owner_id: self.github_owner_id,
            github_repository_id: self.github_repository_id,
            signing_identity: self.signing_identity.clone(),
            license: self.license.clone(),
            reserved_authority: self.reserved_authority.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NamespaceClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NamespaceClaimWire::deserialize(deserializer)?;
        Self::new(
            wire.namespace,
            wire.owner,
            wire.security_contact,
            wire.repository_url,
            wire.github_owner_id,
            wire.github_repository_id,
            wire.signing_identity,
            wire.license,
            wire.reserved_authority,
        )
        .map_err(de::Error::custom)
    }
}

/// A three-party namespace ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceTransfer {
    namespace: Namespace,
    from_owner: ActorId,
    to_owner: ActorId,
    outgoing_authorization: EventAuthorization,
    incoming_acceptance: EventAuthorization,
    index_review_authorization: EventAuthorization,
    effective_sequence: u64,
}

impl NamespaceTransfer {
    /// Creates a transfer with outgoing-owner, incoming-owner, and index-review
    /// authorization evidence.
    pub fn new(
        namespace: Namespace,
        from_owner: ActorId,
        to_owner: ActorId,
        outgoing_authorization: EventAuthorization,
        incoming_acceptance: EventAuthorization,
        index_review_authorization: EventAuthorization,
        effective_sequence: u64,
    ) -> IndexResult<Self> {
        if from_owner == to_owner {
            return Err(IndexError::InvalidEvent("namespace owner does not change"));
        }
        if effective_sequence == 0 {
            return Err(IndexError::InvalidEvent(
                "namespace transfer sequence must be non-zero",
            ));
        }
        if outgoing_authorization.actor() != &from_owner {
            return Err(IndexError::InvalidEvent(
                "outgoing authorization actor does not match owner",
            ));
        }
        if incoming_acceptance.actor() != &to_owner {
            return Err(IndexError::InvalidEvent(
                "incoming acceptance actor does not match owner",
            ));
        }
        Ok(Self {
            namespace,
            from_owner,
            to_owner,
            outgoing_authorization,
            incoming_acceptance,
            index_review_authorization,
            effective_sequence,
        })
    }

    /// Namespace being transferred.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Outgoing owner.
    pub fn from_owner(&self) -> &ActorId {
        &self.from_owner
    }

    /// Incoming owner.
    pub fn to_owner(&self) -> &ActorId {
        &self.to_owner
    }

    /// Outgoing owner's authorization evidence.
    pub fn outgoing_authorization(&self) -> &EventAuthorization {
        &self.outgoing_authorization
    }

    /// Incoming owner's acceptance evidence.
    pub fn incoming_acceptance(&self) -> &EventAuthorization {
        &self.incoming_acceptance
    }

    /// Index review authorization evidence.
    pub fn index_review_authorization(&self) -> &EventAuthorization {
        &self.index_review_authorization
    }

    /// Global event sequence at which this transfer takes effect.
    pub const fn effective_sequence(&self) -> u64 {
        self.effective_sequence
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_text(&mut bytes, self.namespace.as_str());
        put_text(&mut bytes, self.from_owner.as_str());
        put_text(&mut bytes, self.to_owner.as_str());
        bytes.extend_from_slice(&self.outgoing_authorization.canonical_bytes());
        bytes.extend_from_slice(&self.incoming_acceptance.canonical_bytes());
        bytes.extend_from_slice(&self.index_review_authorization.canonical_bytes());
        put_u64(&mut bytes, self.effective_sequence);
        bytes
    }
}

#[derive(Serialize, Deserialize)]
struct NamespaceTransferWire {
    namespace: Namespace,
    from_owner: ActorId,
    to_owner: ActorId,
    outgoing_authorization: EventAuthorization,
    incoming_acceptance: EventAuthorization,
    index_review_authorization: EventAuthorization,
    effective_sequence: u64,
}

impl Serialize for NamespaceTransfer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NamespaceTransferWire {
            namespace: self.namespace.clone(),
            from_owner: self.from_owner.clone(),
            to_owner: self.to_owner.clone(),
            outgoing_authorization: self.outgoing_authorization.clone(),
            incoming_acceptance: self.incoming_acceptance.clone(),
            index_review_authorization: self.index_review_authorization.clone(),
            effective_sequence: self.effective_sequence,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NamespaceTransfer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NamespaceTransferWire::deserialize(deserializer)?;
        Self::new(
            wire.namespace,
            wire.from_owner,
            wire.to_owner,
            wire.outgoing_authorization,
            wire.incoming_acceptance,
            wire.index_review_authorization,
            wire.effective_sequence,
        )
        .map_err(de::Error::custom)
    }
}

/// A validated HTTPS mirror URL.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MirrorUrl(String);

impl MirrorUrl {
    /// Creates a mirror URL.  Index mirrors are HTTPS-only to keep locator
    /// transport separate from digest identity.
    pub fn new(value: impl Into<String>) -> IndexResult<Self> {
        let value = value.into();
        // `url::Url` normalizes dot segments while parsing (for example
        // `/a/../b` becomes `/b`).  Inspect the raw path first so traversal
        // is rejected rather than silently canonicalized away.
        let authority_and_path =
            value
                .strip_prefix("https://")
                .ok_or_else(|| IndexError::InvalidValue {
                    kind: "mirror URL",
                    value: value.clone(),
                })?;
        let path_start = authority_and_path
            .find(['/', '?', '#'])
            .unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..path_start];
        let raw_path = &authority_and_path[path_start..];
        let raw_path = raw_path.split(['?', '#']).next().unwrap_or(raw_path);
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains(':')
            || authority
                .chars()
                .any(|character| character.is_ascii_whitespace() || character.is_control())
            || raw_path.contains('%')
            || raw_path.contains('\\')
            || raw_path.split('/').any(|part| part == "." || part == "..")
        {
            return Err(IndexError::InvalidValue {
                kind: "mirror URL",
                value,
            });
        }
        let lower = value.to_ascii_lowercase();
        let raw_path_has_traversal = value
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').map(|index| &rest[index..]))
            .is_some_and(|path| path.split('/').any(|part| part == "." || part == ".."));
        let parsed = url::Url::parse(&value).map_err(|_| IndexError::InvalidValue {
            kind: "mirror URL",
            value: value.clone(),
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || value.contains('\\')
            || raw_path_has_traversal
            || lower.contains("%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
            || parsed.path_segments().is_some_and(|segments| {
                segments.into_iter().any(|part| part == "." || part == "..")
            })
        {
            return Err(IndexError::InvalidValue {
                kind: "mirror URL",
                value,
            });
        }
        Ok(Self(parsed.to_string()))
    }

    /// Returns the URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MirrorUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for MirrorUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MirrorUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Append-only event kinds that can change a publication's derived state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IndexEventKind {
    /// Exclude the publication from new resolution.
    Yank,
    /// Re-include a yanked publication for new resolution.
    Unyank,
    /// Mark the publication as discouraged while retaining resolution.
    Deprecate,
    /// Block the publication, including locked installs.
    Revoke,
    /// Remove the publication from ordinary discovery.
    Tombstone,
    /// Change publication ownership.
    OwnerChange,
    /// Add an artifact mirror locator.
    AddMirror,
    /// Add a signed/externally verifiable attestation digest.
    AddAttestation,
    /// Add a human/tool annotation.
    Annotation,
}

/// One append-only lifecycle or metadata event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IndexEvent {
    /// Yank a publication from new resolution.
    Yank {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Optional reason.
        reason: Option<String>,
    },
    /// Remove a prior yank.
    Unyank {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
    },
    /// Mark a publication deprecated.
    Deprecate {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Optional replacement coordinate/version.
        replacement: Option<PublicationKey>,
        /// Optional human-readable note.
        note: Option<String>,
    },
    /// Revoke a publication fail-closed.
    Revoke {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Required reason.
        reason: String,
    },
    /// Tombstone a publication from ordinary discovery.
    Tombstone {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Required reason.
        reason: String,
    },
    /// Change the recorded owner.
    OwnerChange {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Expected current owner.
        from: ActorId,
        /// New owner.
        to: ActorId,
    },
    /// Add a content-addressed mirror locator.
    AddMirror {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Mirror URL.
        mirror: MirrorUrl,
    },
    /// Add an attestation digest.
    AddAttestation {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Attestation digest.
        attestation: Digest,
    },
    /// Add an annotation.
    Annotation {
        /// Authorization-relevant actor.
        actor: ActorId,
        /// Target publication.
        publication: PublicationKey,
        /// Annotation key.
        key: String,
        /// Annotation value.
        value: String,
    },
}

impl IndexEvent {
    /// Constructs a yank event.
    pub fn yank(actor: ActorId, publication: PublicationKey, reason: Option<String>) -> Self {
        Self::Yank {
            actor,
            publication,
            reason,
        }
    }

    /// Constructs an unyank event.
    pub fn unyank(actor: ActorId, publication: PublicationKey) -> Self {
        Self::Unyank { actor, publication }
    }

    /// Constructs a deprecation event.
    pub fn deprecate(
        actor: ActorId,
        publication: PublicationKey,
        replacement: Option<PublicationKey>,
        note: Option<String>,
    ) -> Self {
        Self::Deprecate {
            actor,
            publication,
            replacement,
            note,
        }
    }

    /// Constructs a revoke event.
    pub fn revoke(actor: ActorId, publication: PublicationKey, reason: String) -> Self {
        Self::Revoke {
            actor,
            publication,
            reason,
        }
    }

    /// Constructs a tombstone event.
    pub fn tombstone(actor: ActorId, publication: PublicationKey, reason: String) -> Self {
        Self::Tombstone {
            actor,
            publication,
            reason,
        }
    }

    /// Constructs an owner-change event.
    pub fn owner_change(
        actor: ActorId,
        publication: PublicationKey,
        from: ActorId,
        to: ActorId,
    ) -> Self {
        Self::OwnerChange {
            actor,
            publication,
            from,
            to,
        }
    }

    /// Constructs a mirror event.
    pub fn add_mirror(actor: ActorId, publication: PublicationKey, mirror: MirrorUrl) -> Self {
        Self::AddMirror {
            actor,
            publication,
            mirror,
        }
    }

    /// Constructs an attestation event.
    pub fn add_attestation(
        actor: ActorId,
        publication: PublicationKey,
        attestation: Digest,
    ) -> Self {
        Self::AddAttestation {
            actor,
            publication,
            attestation,
        }
    }

    /// Constructs an annotation event.
    pub fn annotation(
        actor: ActorId,
        publication: PublicationKey,
        key: String,
        value: String,
    ) -> Self {
        Self::Annotation {
            actor,
            publication,
            key,
            value,
        }
    }

    /// Event kind.
    pub fn kind(&self) -> IndexEventKind {
        match self {
            Self::Yank { .. } => IndexEventKind::Yank,
            Self::Unyank { .. } => IndexEventKind::Unyank,
            Self::Deprecate { .. } => IndexEventKind::Deprecate,
            Self::Revoke { .. } => IndexEventKind::Revoke,
            Self::Tombstone { .. } => IndexEventKind::Tombstone,
            Self::OwnerChange { .. } => IndexEventKind::OwnerChange,
            Self::AddMirror { .. } => IndexEventKind::AddMirror,
            Self::AddAttestation { .. } => IndexEventKind::AddAttestation,
            Self::Annotation { .. } => IndexEventKind::Annotation,
        }
    }

    /// Target publication key.
    pub fn publication(&self) -> &PublicationKey {
        match self {
            Self::Yank { publication, .. }
            | Self::Unyank { publication, .. }
            | Self::Deprecate { publication, .. }
            | Self::Revoke { publication, .. }
            | Self::Tombstone { publication, .. }
            | Self::OwnerChange { publication, .. }
            | Self::AddMirror { publication, .. }
            | Self::AddAttestation { publication, .. }
            | Self::Annotation { publication, .. } => publication,
        }
    }

    /// Authorization-relevant actor identity.
    pub fn actor(&self) -> &ActorId {
        match self {
            Self::Yank { actor, .. }
            | Self::Unyank { actor, .. }
            | Self::Deprecate { actor, .. }
            | Self::Revoke { actor, .. }
            | Self::Tombstone { actor, .. }
            | Self::OwnerChange { actor, .. }
            | Self::AddMirror { actor, .. }
            | Self::AddAttestation { actor, .. }
            | Self::Annotation { actor, .. } => actor,
        }
    }

    fn validate(&self) -> IndexResult<()> {
        match self {
            Self::Revoke { reason, .. } | Self::Tombstone { reason, .. }
                if reason.trim().is_empty() =>
            {
                Err(IndexError::InvalidEvent("reason is empty"))
            },
            Self::Annotation { key, .. } if key.trim().is_empty() => {
                Err(IndexError::InvalidEvent("annotation key is empty"))
            },
            Self::Annotation { key, value, .. } if key.contains('\0') || value.contains('\0') => {
                Err(IndexError::InvalidEvent("annotation contains NUL"))
            },
            Self::OwnerChange { from, to, .. } if from == to => {
                Err(IndexError::InvalidEvent("owner does not change"))
            },
            _ => Ok(()),
        }
    }
}

/// Bodies accepted by an append-only event envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EventBody {
    /// A publication lifecycle/metadata event.
    Publication(IndexEvent),
    /// A namespace ownership transfer.
    NamespaceTransfer(NamespaceTransfer),
}

impl EventBody {
    /// Returns a publication event body, if present.
    pub fn publication(&self) -> Option<&IndexEvent> {
        match self {
            Self::Publication(event) => Some(event),
            Self::NamespaceTransfer(_) => None,
        }
    }

    /// Returns a namespace transfer body, if present.
    pub fn namespace_transfer(&self) -> Option<&NamespaceTransfer> {
        match self {
            Self::Publication(_) => None,
            Self::NamespaceTransfer(transfer) => Some(transfer),
        }
    }
}

fn put_publication_key(bytes: &mut Vec<u8>, key: &PublicationKey) {
    put_text(bytes, key.index_id.as_str());
    put_text(bytes, key.coordinate.namespace.as_str());
    put_text(bytes, key.coordinate.name.as_str());
    put_text(bytes, &key.version.to_string());
}

fn put_optional_publication_key(bytes: &mut Vec<u8>, key: Option<&PublicationKey>) {
    match key {
        Some(key) => {
            bytes.push(1);
            put_publication_key(bytes, key);
        },
        None => bytes.push(0),
    }
}

fn put_index_event(bytes: &mut Vec<u8>, event: &IndexEvent) {
    match event {
        IndexEvent::Yank {
            actor,
            publication,
            reason,
        } => {
            put_text(bytes, "yank");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_optional_text(bytes, reason.as_deref());
        },
        IndexEvent::Unyank { actor, publication } => {
            put_text(bytes, "unyank");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
        },
        IndexEvent::Deprecate {
            actor,
            publication,
            replacement,
            note,
        } => {
            put_text(bytes, "deprecate");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_optional_publication_key(bytes, replacement.as_ref());
            put_optional_text(bytes, note.as_deref());
        },
        IndexEvent::Revoke {
            actor,
            publication,
            reason,
        } => {
            put_text(bytes, "revoke");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_text(bytes, reason);
        },
        IndexEvent::Tombstone {
            actor,
            publication,
            reason,
        } => {
            put_text(bytes, "tombstone");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_text(bytes, reason);
        },
        IndexEvent::OwnerChange {
            actor,
            publication,
            from,
            to,
        } => {
            put_text(bytes, "owner-change");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_text(bytes, from.as_str());
            put_text(bytes, to.as_str());
        },
        IndexEvent::AddMirror {
            actor,
            publication,
            mirror,
        } => {
            put_text(bytes, "add-mirror");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_text(bytes, mirror.as_str());
        },
        IndexEvent::AddAttestation {
            actor,
            publication,
            attestation,
        } => {
            put_text(bytes, "add-attestation");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_digest(bytes, attestation);
        },
        IndexEvent::Annotation {
            actor,
            publication,
            key,
            value,
        } => {
            put_text(bytes, "annotation");
            put_text(bytes, actor.as_str());
            put_publication_key(bytes, publication);
            put_text(bytes, key);
            put_text(bytes, value);
        },
    }
}

fn put_event_body(bytes: &mut Vec<u8>, body: &EventBody) {
    match body {
        EventBody::Publication(event) => {
            put_text(bytes, "publication");
            put_index_event(bytes, event);
        },
        EventBody::NamespaceTransfer(transfer) => {
            put_text(bytes, "namespace-transfer");
            bytes.extend_from_slice(&transfer.canonical_bytes());
        },
    }
}

/// A sealed, hash-chained event envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    schema: SchemaVersion,
    index: IndexIdentity,
    sequence: u64,
    recorded_at: String,
    actor: ActorId,
    authorization: EventAuthorization,
    prior_event_digest: Option<Digest>,
    body: EventBody,
    event_digest: Digest,
}

impl EventEnvelope {
    /// Seals one event envelope and computes its domain-separated BLAKE3
    /// event digest.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        schema: SchemaVersion,
        index: IndexIdentity,
        sequence: u64,
        recorded_at: impl Into<String>,
        actor: ActorId,
        authorization: EventAuthorization,
        prior_event_digest: Option<Digest>,
        body: EventBody,
    ) -> IndexResult<Self> {
        if schema.as_str() != EVENT_SCHEMA_V1 {
            return Err(IndexError::InvalidEvent(
                "unsupported event envelope schema",
            ));
        }
        if sequence == 0 {
            return Err(IndexError::InvalidEvent("event sequence must be non-zero"));
        }
        let recorded_at = canonical_rfc3339_utc(&recorded_at.into())?;
        if (sequence == 1 && prior_event_digest.is_some())
            || (sequence > 1 && prior_event_digest.is_none())
        {
            return Err(IndexError::InvalidEvent(
                "event prior digest does not match sequence",
            ));
        }
        match &body {
            EventBody::Publication(event) => {
                event.validate()?;
                if event.actor() != &actor {
                    return Err(IndexError::InvalidEvent(
                        "envelope actor does not match event actor",
                    ));
                }
                if event.publication().index_id != index.id {
                    return Err(IndexError::WrongIndex {
                        event: event.publication().index_id.clone(),
                        expected: index.id.clone(),
                    });
                }
            },
            EventBody::NamespaceTransfer(transfer) => {
                if transfer.index_review_authorization().actor() != &actor {
                    return Err(IndexError::InvalidEvent(
                        "envelope actor does not match review authorization",
                    ));
                }
            },
        }
        if authorization.actor() != &actor {
            return Err(IndexError::InvalidEvent(
                "envelope actor does not match authorization evidence",
            ));
        }
        let mut envelope = Self {
            schema,
            index,
            sequence,
            recorded_at,
            actor,
            authorization,
            prior_event_digest,
            body,
            event_digest: Digest::blake3(&[0; 32]),
        };
        envelope.event_digest = Digest::blake3(&envelope.domain_separated_bytes());
        Ok(envelope)
    }

    /// Alias for [`EventEnvelope::seal`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: SchemaVersion,
        index: IndexIdentity,
        sequence: u64,
        recorded_at: impl Into<String>,
        actor: ActorId,
        authorization: EventAuthorization,
        prior_event_digest: Option<Digest>,
        body: EventBody,
    ) -> IndexResult<Self> {
        Self::seal(
            schema,
            index,
            sequence,
            recorded_at,
            actor,
            authorization,
            prior_event_digest,
            body,
        )
    }

    /// Event-envelope schema.
    pub fn schema(&self) -> &SchemaVersion {
        &self.schema
    }

    /// Bound index identity.
    pub fn index(&self) -> &IndexIdentity {
        &self.index
    }

    /// Contiguous event sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Canonical RFC3339 UTC recording time.
    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }

    /// Envelope actor.
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// Detached authorization evidence.
    pub fn authorization(&self) -> &EventAuthorization {
        &self.authorization
    }

    /// Digest of the previous envelope, if this is not sequence one.
    pub fn prior_event_digest(&self) -> Option<&Digest> {
        self.prior_event_digest.as_ref()
    }

    /// Sealed event body.
    pub fn body(&self) -> &EventBody {
        &self.body
    }

    /// Event identity digest.
    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    /// Canonical bytes without the domain separator.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_text(&mut bytes, self.schema.as_str());
        put_text(&mut bytes, self.index.id.as_str());
        put_digest(&mut bytes, self.index.trust_root.digest());
        put_u64(&mut bytes, self.sequence);
        put_text(&mut bytes, &self.recorded_at);
        put_text(&mut bytes, self.actor.as_str());
        bytes.extend_from_slice(&self.authorization.canonical_bytes());
        match &self.prior_event_digest {
            Some(digest) => {
                bytes.push(1);
                put_digest(&mut bytes, digest);
            },
            None => bytes.push(0),
        }
        put_event_body(&mut bytes, &self.body);
        bytes
    }

    /// Recomputes and checks the sealed event digest.
    pub fn verify_digest(&self) -> IndexResult<()> {
        let expected = Digest::blake3(&self.domain_separated_bytes());
        if expected == self.event_digest {
            Ok(())
        } else {
            Err(IndexError::PublicationDigestMismatch)
        }
    }

    /// Delegates cryptographic authorization verification to an implementation
    /// supplied by the index/TUF layer.
    pub fn verify_authorization<V: EventAuthorizationVerifier + ?Sized>(
        &self,
        verifier: &V,
    ) -> IndexResult<()> {
        verifier.verify(self)
    }

    fn domain_separated_bytes(&self) -> Vec<u8> {
        let mut bytes = EVENT_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.canonical_bytes());
        bytes
    }
}

#[derive(Serialize, Deserialize)]
struct EventEnvelopeWire {
    schema: SchemaVersion,
    index: IndexIdentity,
    sequence: u64,
    recorded_at: String,
    actor: ActorId,
    authorization: EventAuthorization,
    prior_event_digest: Option<Digest>,
    body: EventBody,
    event_digest: Digest,
}

impl Serialize for EventEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EventEnvelopeWire {
            schema: self.schema.clone(),
            index: self.index.clone(),
            sequence: self.sequence,
            recorded_at: self.recorded_at.clone(),
            actor: self.actor.clone(),
            authorization: self.authorization.clone(),
            prior_event_digest: self.prior_event_digest.clone(),
            body: self.body.clone(),
            event_digest: self.event_digest.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EventEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EventEnvelopeWire::deserialize(deserializer)?;
        let expected = wire.event_digest.clone();
        let envelope = Self::seal(
            wire.schema,
            wire.index,
            wire.sequence,
            wire.recorded_at,
            wire.actor,
            wire.authorization,
            wire.prior_event_digest,
            wire.body,
        )
        .map_err(de::Error::custom)?;
        if envelope.event_digest != expected {
            return Err(de::Error::custom(IndexError::PublicationDigestMismatch));
        }
        Ok(envelope)
    }
}

fn canonical_rfc3339_utc(value: &str) -> IndexResult<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = bytes.get(range)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            slice
                .iter()
                .fold(0, |total, digit| total * 10 + u32::from(digit - b'0')),
        )
    };
    let year = digits(0..4);
    let month = digits(5..7);
    let day = digits(8..10);
    let hour = digits(11..13);
    let minute = digits(14..16);
    let second = digits(17..19);
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (year, month, day, hour, minute, second)
    else {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year == 0
        || month == 0
        || month > 12
        || day == 0
        || day > month_days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    }
    let suffix = &value[19..];
    if suffix == "Z" {
        return Ok(value.to_owned());
    }
    let Some(fraction) = suffix.strip_prefix('.') else {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    };
    let Some(fraction) = fraction.strip_suffix('Z') else {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    };
    if fraction.is_empty()
        || fraction.len() > 9
        || !fraction.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(IndexError::InvalidValue {
            kind: "RFC3339 UTC timestamp",
            value: value.to_owned(),
        });
    }
    let trimmed = fraction.trim_end_matches('0');
    if trimmed.is_empty() {
        Ok(format!("{}Z", &value[..19]))
    } else {
        Ok(format!("{}.{trimmed}Z", &value[..19]))
    }
}

/// Derived lifecycle state for a publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleState {
    yanked: bool,
    deprecated: bool,
    revoked: bool,
    tombstoned: bool,
    deprecation_replacement: Option<PublicationKey>,
    deprecation_note: Option<String>,
    terminal_reason: Option<String>,
}

impl LifecycleState {
    /// Returns the initial active state.
    pub fn active() -> Self {
        Self {
            yanked: false,
            deprecated: false,
            revoked: false,
            tombstoned: false,
            deprecation_replacement: None,
            deprecation_note: None,
            terminal_reason: None,
        }
    }

    /// True when yanked from new resolution.
    pub const fn is_yanked(&self) -> bool {
        self.yanked
    }

    /// True when deprecated.
    pub const fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// True when revoked.
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// True when tombstoned.
    pub const fn is_tombstoned(&self) -> bool {
        self.tombstoned
    }

    /// True when eligible for a fresh, non-locked resolution.
    pub const fn active_for_new_resolution(&self) -> bool {
        !self.yanked && !self.revoked && !self.tombstoned
    }

    /// True when an existing lock may still use the publication.
    pub const fn allowed_by_lock(&self) -> bool {
        !self.revoked
    }

    /// Optional replacement suggested by deprecation.
    pub fn deprecation_replacement(&self) -> Option<&PublicationKey> {
        self.deprecation_replacement.as_ref()
    }

    /// Optional deprecation note.
    pub fn deprecation_note(&self) -> Option<&str> {
        self.deprecation_note.as_deref()
    }

    /// Terminal reason, if revoked or tombstoned.
    pub fn terminal_reason(&self) -> Option<&str> {
        self.terminal_reason.as_deref()
    }

    fn apply(&mut self, event: &IndexEvent) -> IndexResult<()> {
        event.validate()?;
        if self.tombstoned && !matches!(event, IndexEvent::AddMirror { .. }) {
            return Err(IndexError::InvalidTransition {
                publication: Box::new(event.publication().clone()),
                reason: "only mirror additions are allowed after tombstone",
            });
        }
        match event {
            IndexEvent::Yank { reason, .. } => {
                if self.revoked || self.tombstoned || self.yanked {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(event.publication().clone()),
                        reason: "terminal publication",
                    });
                }
                self.yanked = true;
                if reason.is_some() {
                    self.deprecation_note = reason.clone();
                }
            },
            IndexEvent::Unyank { .. } => {
                if self.revoked || self.tombstoned || !self.yanked {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(event.publication().clone()),
                        reason: if self.yanked {
                            "terminal publication"
                        } else {
                            "publication is not yanked"
                        },
                    });
                }
                self.yanked = false;
            },
            IndexEvent::Deprecate {
                replacement, note, ..
            } => {
                if self.revoked || self.tombstoned || self.deprecated {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(event.publication().clone()),
                        reason: "terminal publication",
                    });
                }
                self.deprecated = true;
                self.deprecation_replacement = replacement.clone();
                self.deprecation_note = note.clone();
            },
            IndexEvent::Revoke { reason, .. } => {
                if self.revoked || self.tombstoned {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(event.publication().clone()),
                        reason: "publication already terminal",
                    });
                }
                self.revoked = true;
                self.terminal_reason = Some(reason.clone());
            },
            IndexEvent::Tombstone { reason, .. } => {
                if self.revoked || self.tombstoned {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(event.publication().clone()),
                        reason: "publication already terminal",
                    });
                }
                self.tombstoned = true;
                self.terminal_reason = Some(reason.clone());
            },
            IndexEvent::OwnerChange { .. }
            | IndexEvent::AddMirror { .. }
            | IndexEvent::AddAttestation { .. }
            | IndexEvent::Annotation { .. } => {},
        }
        Ok(())
    }
}

/// Derives lifecycle state from an ordered event stream.
pub fn derive_lifecycle(events: &[IndexEvent]) -> IndexResult<LifecycleState> {
    let mut state = LifecycleState::active();
    for event in events {
        state.apply(event)?;
    }
    Ok(state)
}

/// In-memory append-only index ledger useful for validation and tests.
#[derive(Clone, Debug)]
pub struct IndexLedger {
    identity: IndexIdentity,
    records: BTreeMap<PublicationKey, PublicationRecord>,
    events: Vec<IndexEvent>,
    event_envelopes: Vec<EventEnvelope>,
    owners: BTreeMap<PublicationKey, ActorId>,
    mirrors: BTreeMap<PublicationKey, BTreeSet<MirrorUrl>>,
    attestations: BTreeMap<PublicationKey, BTreeSet<Digest>>,
    namespace_claims: BTreeMap<Namespace, NamespaceClaim>,
    namespace_owners: BTreeMap<Namespace, ActorId>,
}

impl IndexLedger {
    /// Creates an empty ledger for one trust identity.
    pub fn new(identity: IndexIdentity) -> Self {
        Self {
            identity,
            records: BTreeMap::new(),
            events: Vec::new(),
            event_envelopes: Vec::new(),
            owners: BTreeMap::new(),
            mirrors: BTreeMap::new(),
            attestations: BTreeMap::new(),
            namespace_claims: BTreeMap::new(),
            namespace_owners: BTreeMap::new(),
        }
    }

    /// Index identity.
    pub fn identity(&self) -> &IndexIdentity {
        &self.identity
    }

    /// Immutable records in key order.
    pub fn records(&self) -> impl ExactSizeIterator<Item = &PublicationRecord> {
        self.records.values()
    }

    /// Append-only event history.
    pub fn events(&self) -> &[IndexEvent] {
        &self.events
    }

    /// Sealed event-envelope history, in contiguous sequence order.
    pub fn event_envelopes(&self) -> &[EventEnvelope] {
        &self.event_envelopes
    }

    /// Registers an immutable namespace claim for this index.
    pub fn register_namespace_claim(&mut self, claim: NamespaceClaim) -> IndexResult<()> {
        claim.validate_for_index(&self.identity.id)?;
        let namespace = claim.namespace().clone();
        if self.namespace_claims.contains_key(&namespace) {
            return Err(IndexError::InvalidEvent("namespace is already claimed"));
        }
        self.namespace_owners
            .insert(namespace.clone(), claim.owner().clone());
        self.namespace_claims.insert(namespace, claim);
        Ok(())
    }

    /// Immutable namespace claims in canonical namespace order.
    pub fn namespace_claims(&self) -> impl ExactSizeIterator<Item = &NamespaceClaim> {
        self.namespace_claims.values()
    }

    /// Returns the immutable claim for a namespace.
    pub fn namespace_claim(&self, namespace: &Namespace) -> Option<&NamespaceClaim> {
        self.namespace_claims.get(namespace)
    }

    /// Returns the current owner after any accepted transfers.
    pub fn namespace_owner(&self, namespace: &Namespace) -> Option<&ActorId> {
        self.namespace_owners.get(namespace)
    }

    /// Publishes a record, rejecting same-key equivocation and preserving
    /// idempotent resubmission.
    pub fn publish(&mut self, record: PublicationRecord) -> IndexResult<PublicationClassification> {
        if record.index_id() != &self.identity.id {
            return Err(IndexError::WrongIndex {
                event: record.index_id().clone(),
                expected: self.identity.id.clone(),
            });
        }
        let key = record.key();
        match self.records.get(&key) {
            None => {
                self.owners
                    .insert(key.clone(), record.publisher().actor().clone());
                self.records.insert(key, record);
                Ok(PublicationClassification::New)
            },
            Some(existing) if existing.publication_digest() == record.publication_digest() => {
                Ok(PublicationClassification::Idempotent)
            },
            Some(_) => Err(IndexError::Equivocation(Box::new(key))),
        }
    }

    /// Appends and validates one event.
    pub fn append_event(&mut self, event: IndexEvent) -> IndexResult<()> {
        if !self.event_envelopes.is_empty() {
            return Err(IndexError::InvalidEvent(
                "cannot append an unsealed event after envelopes",
            ));
        }
        self.apply_publication_event(&event)?;
        self.events.push(event);
        Ok(())
    }

    /// Appends a sealed event envelope, enforcing index binding, contiguous
    /// sequence numbers, prior-digest chaining, and structural authorization.
    pub fn append_envelope(&mut self, envelope: EventEnvelope) -> IndexResult<()> {
        envelope.verify_digest()?;
        if envelope.index() != &self.identity {
            return Err(IndexError::WrongIndex {
                event: envelope.index().id.clone(),
                expected: self.identity.id.clone(),
            });
        }
        let expected_sequence = self.event_envelopes.len() as u64 + 1;
        if envelope.sequence() != expected_sequence {
            return Err(IndexError::InvalidEvent("event sequence is not contiguous"));
        }
        let expected_prior = self
            .event_envelopes
            .last()
            .map(|prior| prior.event_digest());
        match (expected_prior, envelope.prior_event_digest()) {
            (None, None) => {},
            (Some(expected), Some(actual)) if expected == actual => {},
            _ => {
                return Err(IndexError::InvalidEvent(
                    "event prior digest chain mismatch",
                ));
            },
        }
        match envelope.body() {
            EventBody::Publication(event) => {
                self.apply_publication_event(event)?;
                self.events.push(event.clone());
            },
            EventBody::NamespaceTransfer(transfer) => {
                self.apply_namespace_transfer(transfer, envelope.sequence())?;
            },
        }
        self.event_envelopes.push(envelope);
        Ok(())
    }

    /// Alias for [`IndexLedger::append_envelope`].
    pub fn append_event_envelope(&mut self, envelope: EventEnvelope) -> IndexResult<()> {
        self.append_envelope(envelope)
    }

    fn apply_publication_event(&mut self, event: &IndexEvent) -> IndexResult<()> {
        event.validate()?;
        if event.publication().index_id != self.identity.id {
            return Err(IndexError::WrongIndex {
                event: event.publication().index_id.clone(),
                expected: self.identity.id.clone(),
            });
        }
        let key = event.publication().clone();
        if !self.records.contains_key(&key) {
            return Err(IndexError::UnknownPublication(Box::new(key)));
        }
        let prior_events: Vec<IndexEvent> = self
            .events
            .iter()
            .filter(|prior| prior.publication() == &key)
            .cloned()
            .collect();
        let mut state = derive_lifecycle(&prior_events)?;
        state.apply(event)?;

        match &event {
            IndexEvent::OwnerChange { from, to, .. } => {
                if let Some(current) = self.owners.get(&key)
                    && current != from
                {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(key),
                        reason: "owner precondition does not match",
                    });
                }
                if let Some(current) = self.owners.get(&key)
                    && event.actor() != current
                {
                    return Err(IndexError::InvalidTransition {
                        publication: Box::new(key),
                        reason: "actor is not current owner",
                    });
                }
                self.owners.insert(key.clone(), to.clone());
            },
            IndexEvent::AddMirror { mirror, .. } => {
                let inserted = self
                    .mirrors
                    .entry(key.clone())
                    .or_default()
                    .insert(mirror.clone());
                if !inserted {
                    return Err(IndexError::InvalidEvent("duplicate mirror"));
                }
            },
            IndexEvent::AddAttestation { attestation, .. } => {
                let inserted = self
                    .attestations
                    .entry(key.clone())
                    .or_default()
                    .insert(attestation.clone());
                if !inserted {
                    return Err(IndexError::InvalidEvent("duplicate attestation"));
                }
            },
            _ => {},
        }
        Ok(())
    }

    fn apply_namespace_transfer(
        &mut self,
        transfer: &NamespaceTransfer,
        sequence: u64,
    ) -> IndexResult<()> {
        if transfer.effective_sequence() != sequence {
            return Err(IndexError::InvalidEvent(
                "namespace transfer effective sequence does not match envelope",
            ));
        }
        let namespace = transfer.namespace();
        let claim = self
            .namespace_claims
            .get(namespace)
            .ok_or(IndexError::InvalidEvent(
                "namespace claim is not registered",
            ))?;
        claim.validate_for_index(&self.identity.id)?;
        let current = self
            .namespace_owners
            .get(namespace)
            .ok_or(IndexError::InvalidEvent(
                "namespace owner is not registered",
            ))?;
        if current != transfer.from_owner() {
            return Err(IndexError::InvalidEvent(
                "namespace transfer outgoing owner is stale",
            ));
        }
        self.namespace_owners
            .insert(namespace.clone(), transfer.to_owner().clone());
        Ok(())
    }

    /// Gets a record by key.
    pub fn get(&self, key: &PublicationKey) -> Option<&PublicationRecord> {
        self.records.get(key)
    }

    /// Gets the derived state of a record.
    pub fn lifecycle(&self, key: &PublicationKey) -> IndexResult<LifecycleState> {
        if !self.records.contains_key(key) {
            return Err(IndexError::UnknownPublication(Box::new(key.clone())));
        }
        let events: Vec<IndexEvent> = self
            .events
            .iter()
            .filter(|event| event.publication() == key)
            .cloned()
            .collect();
        derive_lifecycle(&events)
    }

    /// Returns the current owner when owner-change events have established one.
    pub fn owner(&self, key: &PublicationKey) -> Option<&ActorId> {
        self.owners.get(key)
    }
}

/// A lock entry binding resolution to one index and immutable content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockRecord {
    index_id: IndexId,
    trust_root: TrustRootFingerprint,
    coordinate: Coordinate,
    version: CanonicalSemVer,
    publication_digest: Digest,
    artifact_digests: Vec<Digest>,
    artifact_size: u64,
    artifact_media_type: String,
    manifest_digest: Digest,
    component_digest: Digest,
    wit_digest: Digest,
    capability_digest: Digest,
    ipc_digest: Digest,
    runtime_abi_digest: Digest,
    dependency_digest: Digest,
    provenance_digest: Digest,
    source_digest: Digest,
}

impl LockRecord {
    /// Creates a lock bound to an index identity and publication.
    pub fn from_publication(identity: &IndexIdentity, record: &PublicationRecord) -> Self {
        Self {
            index_id: identity.id.clone(),
            trust_root: identity.trust_root.clone(),
            coordinate: record.coordinate.clone(),
            version: record.version.clone(),
            publication_digest: record.publication_digest.clone(),
            artifact_digests: record.artifact.digests.clone(),
            artifact_size: record.artifact.size,
            artifact_media_type: record.artifact.media_type.clone(),
            manifest_digest: record.manifest_digest().clone(),
            component_digest: record.component_digest().clone(),
            wit_digest: record.wit_digest().clone(),
            capability_digest: record.capability_digest().clone(),
            ipc_digest: record.capabilities().effective_ipc_digest().clone(),
            runtime_abi_digest: record.runtime().digest().clone(),
            dependency_digest: record.dependency_digest().clone(),
            provenance_digest: record.provenance_digest().clone(),
            source_digest: record.source_digest().clone(),
        }
    }

    /// Index ID in the lock.
    pub fn index_id(&self) -> &IndexId {
        &self.index_id
    }

    /// Trust-root fingerprint in the lock.
    pub fn trust_root(&self) -> &TrustRootFingerprint {
        &self.trust_root
    }

    /// Coordinate in the lock.
    pub fn coordinate(&self) -> &Coordinate {
        &self.coordinate
    }

    /// Version in the lock.
    pub fn version(&self) -> &CanonicalSemVer {
        &self.version
    }

    /// Publication digest in the lock.
    pub fn publication_digest(&self) -> &Digest {
        &self.publication_digest
    }

    /// Checks index identity and every immutable content binding.
    pub fn verify(&self, identity: &IndexIdentity, record: &PublicationRecord) -> IndexResult<()> {
        if self.index_id != identity.id || self.trust_root != identity.trust_root {
            return Err(IndexError::LockIndexMismatch);
        }
        if self.coordinate != *record.coordinate()
            || self.version != *record.version()
            || self.publication_digest != *record.publication_digest()
            || self.artifact_digests != record.artifact().digests()
            || self.artifact_size != record.artifact().size()
            || self.artifact_media_type != record.artifact().media_type()
            || self.manifest_digest != *record.manifest_digest()
            || self.component_digest != *record.component_digest()
            || self.wit_digest != *record.wit_digest()
            || self.capability_digest != *record.capability_digest()
            || self.ipc_digest != *record.capabilities().effective_ipc_digest()
            || self.runtime_abi_digest != *record.runtime().digest()
            || self.dependency_digest != *record.dependency_digest()
            || self.provenance_digest != *record.provenance_digest()
            || self.source_digest != *record.source_digest()
        {
            return Err(IndexError::LockMismatch(Box::new(record.key())));
        }
        Ok(())
    }
}

/// A selected publication and its derived state.
#[derive(Clone, Debug)]
pub struct ResolvedPublication<'a> {
    /// Selected immutable record.
    pub record: &'a PublicationRecord,
    /// State derived from events.
    pub state: LifecycleState,
}

/// Deterministic resolver over an index snapshot.
#[derive(Debug)]
pub struct Resolver<'a> {
    identity: IndexIdentity,
    records: &'a [PublicationRecord],
    events: &'a [IndexEvent],
}

impl<'a> Resolver<'a> {
    /// Creates a resolver over records and append-only events.
    pub fn new(
        identity: IndexIdentity,
        records: &'a [PublicationRecord],
        events: &'a [IndexEvent],
    ) -> Self {
        Self {
            identity,
            records,
            events,
        }
    }

    /// Resolves the highest compatible stable publication.  A SemVer
    /// requirement containing a prerelease comparator explicitly opts into
    /// prerelease candidates.
    pub fn resolve(
        &self,
        coordinate: &Coordinate,
        requirement: &VersionReq,
    ) -> IndexResult<ResolvedPublication<'a>> {
        self.resolve_inner(coordinate, requirement, None, false)
    }

    /// Resolves with explicit permission to consider prerelease versions.
    pub fn resolve_prerelease(
        &self,
        coordinate: &Coordinate,
        requirement: &VersionReq,
    ) -> IndexResult<ResolvedPublication<'a>> {
        self.resolve_inner(coordinate, requirement, None, true)
    }

    /// Resolves while preserving an existing lock.  A yanked lock remains
    /// usable; a revoked lock fails closed.
    pub fn resolve_with_lock(
        &self,
        coordinate: &Coordinate,
        requirement: &VersionReq,
        lock: &LockRecord,
    ) -> IndexResult<ResolvedPublication<'a>> {
        self.resolve_inner(coordinate, requirement, Some(lock), false)
    }

    /// Resolves an exact lock without applying a new version requirement.
    pub fn resolve_locked(&self, lock: &LockRecord) -> IndexResult<ResolvedPublication<'a>> {
        self.resolve_inner(&lock.coordinate, &VersionReq::STAR, Some(lock), true)
    }

    fn resolve_inner(
        &self,
        coordinate: &Coordinate,
        requirement: &VersionReq,
        lock: Option<&LockRecord>,
        explicit_prerelease: bool,
    ) -> IndexResult<ResolvedPublication<'a>> {
        if let Some(lock) = lock {
            if lock.index_id != self.identity.id || lock.trust_root != self.identity.trust_root {
                return Err(IndexError::LockIndexMismatch);
            }
            let Some(record) = self.records.iter().find(|record| {
                record.coordinate() == &lock.coordinate && record.version() == &lock.version
            }) else {
                return Err(IndexError::LockMismatch(Box::new(PublicationKey::new(
                    lock.index_id.clone(),
                    lock.coordinate.clone(),
                    lock.version.clone(),
                ))));
            };
            lock.verify(&self.identity, record)?;
            let state = self.state_for(record.key())?;
            if state.is_revoked() {
                return Err(IndexError::LockedPublicationRevoked(Box::new(record.key())));
            }
            if record.coordinate() != coordinate
                || !requirement.matches(record.version().as_version())
            {
                return Err(IndexError::LockMismatch(Box::new(record.key())));
            }
            return Ok(ResolvedPublication { record, state });
        }

        let allow_prerelease = explicit_prerelease || requirement.to_string().contains('-');
        let mut candidates: Vec<(&PublicationRecord, LifecycleState)> = Vec::new();
        for record in self.records {
            if record.index_id() != &self.identity.id || record.coordinate() != coordinate {
                continue;
            }
            let state = self.state_for(record.key())?;
            if !state.active_for_new_resolution()
                || (!allow_prerelease && record.version().is_prerelease())
                || !requirement.matches(record.version().as_version())
            {
                continue;
            }
            candidates.push((record, state));
        }
        candidates.sort_by(|left, right| {
            left.0.version().cmp(right.0.version()).then_with(|| {
                left.0
                    .publication_digest()
                    .cmp(right.0.publication_digest())
            })
        });
        candidates
            .pop()
            .map(|(record, state)| ResolvedPublication { record, state })
            .ok_or_else(|| IndexError::NoMatchingPublication {
                coordinate: coordinate.clone(),
            })
    }

    fn state_for(&self, key: PublicationKey) -> IndexResult<LifecycleState> {
        let events: Vec<IndexEvent> = self
            .events
            .iter()
            .filter(|event| event.publication() == &key)
            .cloned()
            .collect();
        derive_lifecycle(&events)
    }
}

/// Compatibility alias used by callers that name the version type `SemVer`.
pub type SemVer = CanonicalSemVer;

/// Compatibility alias for a lockfile entry.
pub type LockfileEntry = LockRecord;

/// Compatibility alias for a publication identity digest.
pub type PublicationDigest = Digest;

#[cfg(test)]
mod tests;
