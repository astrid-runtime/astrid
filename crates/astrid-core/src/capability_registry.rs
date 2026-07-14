//! Content-addressed capability registry primitives.
//!
//! Exact capability identifiers, semantic entry digests, content-bound
//! references, and canonical registry manifests.

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use thiserror::Error;

use crate::capability_grammar::{
    CapabilityDanger, CapabilityGrammarError, CapabilityScope, validate_capability,
};

const ENTRY_DIGEST_DOMAIN: &[u8] = b"astrid-capability-entry\0";
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"astrid-capability-registry\0";

/// Digest algorithm used by capability entries and registry manifests.
pub const CAPABILITY_REGISTRY_DIGEST_ALGORITHM: &str = "blake3";

/// Exact capability IDs in capability-registry revision 1.
///
/// This set is authority-bearing and frozen for its registry schema revision.
/// Expanding it requires an intentional schema revision and reviewed digest vectors.
const CAPABILITY_REGISTRY_REVISION_1_IDS: [&str; 51] = [
    "system:shutdown",
    "system:status",
    "capsule:install",
    "self:capsule:install",
    "capsule:reload",
    "self:capsule:reload",
    "capsule:remove",
    "self:capsule:remove",
    "self:workspace:promote",
    "self:workspace:rollback",
    "capsule:list",
    "self:capsule:list",
    "agent:create",
    "agent:create:inherit",
    "agent:create:clone",
    "agent:delete",
    "agent:enable",
    "agent:disable",
    "agent:modify",
    "agent:list",
    "self:agent:list",
    "quota:set",
    "self:quota:set",
    "quota:get",
    "self:quota:get",
    "group:create",
    "group:delete",
    "group:modify",
    "group:list",
    "self:group:list",
    "caps:grant",
    "caps:revoke",
    "caps:token:mint",
    "caps:token:revoke",
    "caps:token:list",
    "invite:issue",
    "invite:redeem",
    "invite:list",
    "invite:revoke",
    "audit:read_all",
    "self:approval:respond",
    "self:auth:pair",
    "self:auth:pair:admin",
    "auth:pair:redeem",
    "auth:pair",
    "system:resources:unbounded",
    "net_bind",
    "uplink",
    "capsule:access:any",
    "authority:profile:manage",
    "authority:repair",
];

/// A validated capability identifier containing no wildcard segment.
///
/// The generic storage parameter permits borrowed views at validation and
/// lookup boundaries without changing the owned public representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactCapabilityId<T = String>(T);

impl<T: AsRef<str>> ExactCapabilityId<T> {
    /// Validate an exact capability identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability grammar is invalid or any segment
    /// is the wildcard marker `*`.
    pub fn new(value: T) -> Result<Self, AuthorityRegistryError> {
        let raw = value.as_ref();
        validate_capability(raw).map_err(|source| AuthorityRegistryError::InvalidCapabilityId {
            id: raw.to_string(),
            source,
        })?;
        if raw.split(':').any(|segment| segment == "*") {
            return Err(AuthorityRegistryError::WildcardCapabilityId {
                id: raw.to_string(),
            });
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Borrow the same validated identifier without allocating.
    #[must_use]
    pub fn as_borrowed(&self) -> ExactCapabilityId<&str> {
        ExactCapabilityId(self.as_str())
    }
}

impl<T> ExactCapabilityId<T> {
    /// Consume the wrapper and return its storage.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// BLAKE3 digest of one immutable registered capability definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityEntryDigest<T = [u8; 32]>(T);

impl<T> CapabilityEntryDigest<T> {
    /// Consume the wrapper and return its storage.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsRef<[u8]>> CapabilityEntryDigest<T> {
    /// Validate and wrap digest storage.
    ///
    /// # Errors
    ///
    /// Returns an error unless the storage contains exactly 32 bytes.
    pub fn new(value: T) -> Result<Self, AuthorityRegistryError> {
        let actual = value.as_ref().len();
        if actual != 32 {
            return Err(AuthorityRegistryError::InvalidDigestLength {
                kind: "capability entry",
                actual,
            });
        }
        Ok(Self(value))
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Render the digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl CapabilityEntryDigest {
    /// Wrap a compile-time-sized BLAKE3 digest.
    #[must_use]
    pub const fn from_array(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrow the fixed-size digest array.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

/// BLAKE3 digest of one complete capability-registry manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityRegistryDigest<T = [u8; 32]>(T);

impl<T> CapabilityRegistryDigest<T> {
    /// Consume the wrapper and return its storage.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsRef<[u8]>> CapabilityRegistryDigest<T> {
    /// Validate and wrap digest storage.
    ///
    /// # Errors
    ///
    /// Returns an error unless the storage contains exactly 32 bytes.
    pub fn new(value: T) -> Result<Self, AuthorityRegistryError> {
        let actual = value.as_ref().len();
        if actual != 32 {
            return Err(AuthorityRegistryError::InvalidDigestLength {
                kind: "capability registry",
                actual,
            });
        }
        Ok(Self(value))
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Render the digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl CapabilityRegistryDigest {
    /// Wrap a compile-time-sized BLAKE3 digest.
    #[must_use]
    pub const fn from_array(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrow the fixed-size digest array.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A content-bound reference used on an authority edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityRef<I = String, D = [u8; 32]> {
    id: ExactCapabilityId<I>,
    entry_digest: CapabilityEntryDigest<D>,
}

impl<I, D> CapabilityRef<I, D> {
    /// Construct a reference from an already validated ID and digest.
    #[must_use]
    pub const fn new(id: ExactCapabilityId<I>, entry_digest: CapabilityEntryDigest<D>) -> Self {
        Self { id, entry_digest }
    }

    /// Borrow the exact capability ID.
    #[must_use]
    pub const fn id(&self) -> &ExactCapabilityId<I> {
        &self.id
    }

    /// Borrow the bound registry-entry digest.
    #[must_use]
    pub const fn entry_digest(&self) -> &CapabilityEntryDigest<D> {
        &self.entry_digest
    }

    /// Consume the reference into its parts.
    #[must_use]
    pub fn into_parts(self) -> (ExactCapabilityId<I>, CapabilityEntryDigest<D>) {
        (self.id, self.entry_digest)
    }
}

/// Canonical authorization target families understood by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityTargetKind {
    /// The local Astrid system.
    System,
    /// A principal identity.
    Principal,
    /// A capability-profile or legacy group identity.
    Group,
    /// A device or service credential.
    Credential,
    /// A signed capsule package.
    CapsulePackage,
    /// One installed or running capsule instance.
    CapsuleInstance,
    /// An application-level session.
    ApplicationSession,
    /// A configured model.
    Model,
    /// An audit query or subscription scope.
    AuditScope,
}

impl AuthorityTargetKind {
    const fn code(self) -> u64 {
        match self {
            Self::System => 0,
            Self::Principal => 1,
            Self::Group => 2,
            Self::Credential => 3,
            Self::CapsulePackage => 4,
            Self::CapsuleInstance => 5,
            Self::ApplicationSession => 6,
            Self::Model => 7,
            Self::AuditScope => 8,
        }
    }
}

/// Provenance of a registered capability definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilitySource {
    /// A capability defined by the Astrid host.
    Kernel,
    /// A capability supplied by a verified signed extension package.
    SignedExtension {
        /// BLAKE3 digest of the signed extension package.
        package_digest: [u8; 32],
    },
}

/// One capability definition and its semantic digest.
///
/// `danger` is display metadata and is excluded from entry and manifest digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCapability {
    id: ExactCapabilityId,
    scope: CapabilityScope,
    target_kinds: BTreeSet<AuthorityTargetKind>,
    danger: CapabilityDanger,
    delegable: bool,
    privileged: bool,
    source: CapabilitySource,
    entry_digest: CapabilityEntryDigest,
}

impl RegisteredCapability {
    /// Build and seal a registered capability definition.
    ///
    /// Target order is canonicalized before hashing. At least one target kind
    /// is required so an authority check can never be registered without a
    /// host-owned target domain.
    ///
    /// # Errors
    ///
    /// Returns an error when `target_kinds` is empty.
    pub fn new(
        id: ExactCapabilityId,
        scope: CapabilityScope,
        target_kinds: impl IntoIterator<Item = AuthorityTargetKind>,
        danger: CapabilityDanger,
        delegable: bool,
        privileged: bool,
        source: CapabilitySource,
    ) -> Result<Self, AuthorityRegistryError> {
        let target_kinds = target_kinds.into_iter().collect::<BTreeSet<_>>();
        if target_kinds.is_empty() {
            return Err(AuthorityRegistryError::MissingTargetKind {
                id: id.as_str().to_string(),
            });
        }
        let entry_digest = digest_entry(&id, scope, &target_kinds, delegable, privileged, source);
        Ok(Self {
            id,
            scope,
            target_kinds,
            danger,
            delegable,
            privileged,
            source,
            entry_digest,
        })
    }

    /// Borrow the exact capability ID.
    #[must_use]
    pub const fn id(&self) -> &ExactCapabilityId {
        &self.id
    }

    /// Return the authority scope.
    #[must_use]
    pub const fn scope(&self) -> CapabilityScope {
        self.scope
    }

    /// Borrow the canonical target-kind set.
    #[must_use]
    pub const fn target_kinds(&self) -> &BTreeSet<AuthorityTargetKind> {
        &self.target_kinds
    }

    /// Return the operator-facing danger classification.
    #[must_use]
    pub const fn danger(&self) -> CapabilityDanger {
        self.danger
    }

    /// Whether the registry may generate an exact delegation companion.
    #[must_use]
    pub const fn delegable(&self) -> bool {
        self.delegable
    }

    /// Whether granting this capability is itself privileged authority.
    #[must_use]
    pub const fn privileged(&self) -> bool {
        self.privileged
    }

    /// Return the definition provenance.
    #[must_use]
    pub const fn source(&self) -> CapabilitySource {
        self.source
    }

    /// Return the immutable definition digest.
    #[must_use]
    pub const fn entry_digest(&self) -> CapabilityEntryDigest {
        self.entry_digest
    }

    /// Create the content-bound reference used by authority edges.
    #[must_use]
    pub fn capability_ref(&self) -> CapabilityRef<&str, &[u8; 32]> {
        CapabilityRef::new(
            self.id.as_borrowed(),
            CapabilityEntryDigest(self.entry_digest.as_array()),
        )
    }

    fn verify_digest(&self) -> Result<(), AuthorityRegistryError> {
        let actual = digest_entry(
            &self.id,
            self.scope,
            &self.target_kinds,
            self.delegable,
            self.privileged,
            self.source,
        );
        if actual != self.entry_digest {
            return Err(AuthorityRegistryError::EntryDigestMismatch {
                id: self.id.as_str().to_string(),
                expected: self.entry_digest.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(())
    }
}

/// A sorted, content-addressed registry generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRegistryManifest {
    schema_revision: NonZeroU32,
    entries: Vec<RegisteredCapability>,
    digest: CapabilityRegistryDigest,
}

impl CapabilityRegistryManifest {
    /// Validate, sort, and seal a complete registry manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty registry, a duplicate capability ID, or an
    /// entry whose stored digest does not match its authorization semantics.
    pub fn new(
        schema_revision: NonZeroU32,
        entries: impl IntoIterator<Item = RegisteredCapability>,
    ) -> Result<Self, AuthorityRegistryError> {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        if entries.is_empty() {
            return Err(AuthorityRegistryError::EmptyRegistry);
        }
        for entry in &entries {
            entry.verify_digest()?;
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        for pair in entries.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(AuthorityRegistryError::DuplicateCapabilityId {
                    id: pair[0].id.as_str().to_string(),
                });
            }
        }
        let digest = digest_registry(schema_revision, &entries);
        Ok(Self {
            schema_revision,
            entries,
            digest,
        })
    }

    /// Return the registry schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> NonZeroU32 {
        self.schema_revision
    }

    /// Return the fixed digest algorithm identifier.
    #[must_use]
    pub const fn digest_algorithm(&self) -> &'static str {
        CAPABILITY_REGISTRY_DIGEST_ALGORITHM
    }

    /// Borrow entries in canonical `(id, digest)` order.
    #[must_use]
    pub fn entries(&self) -> &[RegisteredCapability] {
        &self.entries
    }

    /// Return the canonical registry digest.
    #[must_use]
    pub const fn digest(&self) -> CapabilityRegistryDigest {
        self.digest
    }

    /// Resolve an exact content-bound capability reference.
    #[must_use]
    pub fn resolve<I, D>(&self, reference: &CapabilityRef<I, D>) -> Option<&RegisteredCapability>
    where
        I: AsRef<str>,
        D: AsRef<[u8]>,
    {
        let index = self
            .entries
            .binary_search_by(|entry| entry.id.as_str().cmp(reference.id().as_str()))
            .ok()?;
        let entry = &self.entries[index];
        (entry.entry_digest.as_bytes() == reference.entry_digest().as_bytes()).then_some(entry)
    }

    /// Recompute and verify all entry and manifest digests.
    ///
    /// # Errors
    ///
    /// Returns an error if an entry or the aggregate digest has drifted.
    pub fn verify(&self) -> Result<(), AuthorityRegistryError> {
        for entry in &self.entries {
            entry.verify_digest()?;
        }
        let actual = digest_registry(self.schema_revision, &self.entries);
        if actual != self.digest {
            return Err(AuthorityRegistryError::RegistryDigestMismatch {
                expected: self.digest.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(())
    }
}

/// Validation failures for content-addressed authority registry data.
#[derive(Debug, Error)]
pub enum AuthorityRegistryError {
    /// A capability ID failed the existing static capability grammar.
    #[error("invalid capability id {id:?}: {source}")]
    InvalidCapabilityId {
        /// Rejected identifier.
        id: String,
        /// Underlying grammar error.
        #[source]
        source: CapabilityGrammarError,
    },
    /// A grantable capability ID contained a wildcard segment.
    #[error("registered capability id {id:?} must be exact")]
    WildcardCapabilityId {
        /// Rejected identifier.
        id: String,
    },
    /// A capability definition omitted its authorization target domain.
    #[error("registered capability {id:?} must name at least one target kind")]
    MissingTargetKind {
        /// Capability identifier.
        id: String,
    },
    /// A supplied digest did not contain exactly 32 bytes.
    #[error("{kind} digest must contain exactly 32 bytes, got {actual}")]
    InvalidDigestLength {
        /// Digest domain.
        kind: &'static str,
        /// Supplied byte count.
        actual: usize,
    },
    /// A registry contained no definitions.
    #[error("capability registry must contain at least one entry")]
    EmptyRegistry,
    /// A registry assigned more than one definition to a stable ID.
    #[error("capability registry contains more than one definition for {id:?}")]
    DuplicateCapabilityId {
        /// Duplicated capability identifier.
        id: String,
    },
    /// An entry's stored digest did not match its authorization semantics.
    #[error("capability {id:?} digest mismatch: expected {expected}, computed {actual}")]
    EntryDigestMismatch {
        /// Capability identifier.
        id: String,
        /// Stored digest.
        expected: String,
        /// Recomputed digest.
        actual: String,
    },
    /// The aggregate registry digest did not match its entries.
    #[error("capability registry digest mismatch: expected {expected}, computed {actual}")]
    RegistryDigestMismatch {
        /// Stored digest.
        expected: String,
        /// Recomputed digest.
        actual: String,
    },
}

fn digest_entry(
    id: &ExactCapabilityId,
    scope: CapabilityScope,
    target_kinds: &BTreeSet<AuthorityTargetKind>,
    delegable: bool,
    privileged: bool,
    source: CapabilitySource,
) -> CapabilityEntryDigest {
    let mut canonical = Vec::new();
    encode_entry(
        &mut canonical,
        id,
        scope,
        target_kinds,
        delegable,
        privileged,
        source,
    );
    CapabilityEntryDigest::from_array(domain_hash(ENTRY_DIGEST_DOMAIN, &canonical))
}

fn digest_registry(
    schema_revision: NonZeroU32,
    entries: &[RegisteredCapability],
) -> CapabilityRegistryDigest {
    let mut canonical = Vec::new();
    encode_array_len(&mut canonical, 2);
    encode_unsigned(&mut canonical, u64::from(schema_revision.get()));
    encode_array_len(&mut canonical, entries.len());
    for entry in entries {
        encode_entry(
            &mut canonical,
            &entry.id,
            entry.scope,
            &entry.target_kinds,
            entry.delegable,
            entry.privileged,
            entry.source,
        );
    }
    CapabilityRegistryDigest::from_array(domain_hash(REGISTRY_DIGEST_DOMAIN, &canonical))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the tuple is the normative capability entry"
)]
fn encode_entry(
    output: &mut Vec<u8>,
    id: &ExactCapabilityId,
    scope: CapabilityScope,
    target_kinds: &BTreeSet<AuthorityTargetKind>,
    delegable: bool,
    privileged: bool,
    source: CapabilitySource,
) {
    encode_array_len(output, 6);
    encode_text(output, id.as_str());
    encode_unsigned(output, scope_code(scope));
    let mut target_codes = target_kinds
        .iter()
        .map(|target| target.code())
        .collect::<Vec<_>>();
    target_codes.sort_unstable();
    encode_array_len(output, target_codes.len());
    for target_code in target_codes {
        encode_unsigned(output, target_code);
    }
    encode_bool(output, delegable);
    encode_bool(output, privileged);
    encode_source(output, source);
}

const fn scope_code(scope: CapabilityScope) -> u64 {
    match scope {
        CapabilityScope::Self_ => 0,
        CapabilityScope::Global => 1,
    }
}

fn encode_source(output: &mut Vec<u8>, source: CapabilitySource) {
    match source {
        CapabilitySource::Kernel => {
            encode_array_len(output, 1);
            encode_unsigned(output, 0);
        },
        CapabilitySource::SignedExtension { package_digest } => {
            encode_array_len(output, 2);
            encode_unsigned(output, 1);
            encode_bytes(output, &package_digest);
        },
    }
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(canonical);
    *hasher.finalize().as_bytes()
}

fn encode_array_len(output: &mut Vec<u8>, len: usize) {
    encode_major_len(output, 4, usize_to_u64(len));
}

fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_major_len(output, 3, usize_to_u64(value.len()));
    output.extend_from_slice(value.as_bytes());
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_major_len(output, 2, usize_to_u64(value.len()));
    output.extend_from_slice(value);
}

fn encode_unsigned(output: &mut Vec<u8>, value: u64) {
    encode_major_len(output, 0, value);
}

fn encode_bool(output: &mut Vec<u8>, value: bool) {
    output.push(if value { 0xf5 } else { 0xf4 });
}

fn encode_major_len(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if let Ok(value) = u8::try_from(value) {
        if value <= 23 {
            output.push(prefix | value);
        } else {
            output.push(prefix | 0x18);
            output.push(value);
        }
    } else if let Ok(value) = u16::try_from(value) {
        output.push(prefix | 0x19);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push(prefix | 0x1a);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push(prefix | 0x1b);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn usize_to_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => unreachable!("usize always fits into u64 on supported targets"),
    }
}

#[cfg(test)]
mod tests;
