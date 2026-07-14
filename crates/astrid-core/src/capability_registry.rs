//! Content-addressed capability registry primitives.
//!
//! Exact capability identifiers, semantic entry digests, content-bound
//! references, and canonical registry manifests.

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use thiserror::Error;

use crate::capability_grammar::{
    CAPABILITY_CATALOG, CapabilityDanger, CapabilityGrammarError, CapabilityScope,
    validate_capability,
};
use util::{
    domain_hash, encode_array_len, encode_bool, encode_bytes, encode_text, encode_unsigned,
    validate_digest_length,
};

mod util;

const ENTRY_DIGEST_DOMAIN: &[u8] = b"astrid-capability-entry\0";
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"astrid-capability-registry\0";

/// Digest algorithm used by capability entries and registry manifests.
pub const CAPABILITY_REGISTRY_DIGEST_ALGORITHM: &str = "blake3";

/// Nonzero schema revision for a capability-registry manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityRegistryRevision<T = NonZeroU32>(T);

impl<T> CapabilityRegistryRevision<T> {
    /// Consume the wrapper and return its storage.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrow the wrapped revision storage.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }
}

impl CapabilityRegistryRevision {
    /// Wrap a validated nonzero schema revision.
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Return the revision as a primitive integer.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Exact capability IDs in capability-registry revision 1.
///
/// This set is authority-bearing and frozen for its registry schema revision.
/// Expanding it requires an intentional schema revision and reviewed digest vectors.
#[cfg(test)]
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

/// Schema revision for the 51-ID authority registry.
pub const CAPABILITY_REGISTRY_REVISION_1: CapabilityRegistryRevision =
    CapabilityRegistryRevision::new(NonZeroU32::MIN);

#[derive(Clone, Copy)]
struct RevisionSemantics {
    scope: CapabilityScope,
    target_kinds: &'static [AuthorityTargetKind],
    delegable: bool,
    privileged: bool,
}

/// Build the content-addressed registry for the 51 fixed capability IDs.
///
/// # Errors
///
/// Returns an error if an ID lacks fixed semantics or display metadata, or if
/// any definition fails registry validation.
pub fn capability_registry_revision_1() -> Result<CapabilityRegistryManifest, AuthorityRegistryError>
{
    let entries = CAPABILITY_REGISTRY_REVISION_1_IDS
        .into_iter()
        .map(|id| {
            let semantics = revision_1_semantics(id).ok_or_else(|| {
                AuthorityRegistryError::MissingRevisionDefinition { id: id.to_string() }
            })?;
            let danger = revision_1_danger(id).ok_or_else(|| {
                AuthorityRegistryError::MissingRevisionDisplayMetadata { id: id.to_string() }
            })?;
            RegisteredCapability::new(
                ExactCapabilityId::new(id.to_string())?,
                semantics.scope,
                semantics.target_kinds.iter().copied(),
                danger,
                semantics.delegable,
                semantics.privileged,
                CapabilitySource::Kernel,
            )
        })
        .collect::<Result<Vec<_>, AuthorityRegistryError>>()?;

    CapabilityRegistryManifest::new(CAPABILITY_REGISTRY_REVISION_1, entries)
}

fn revision_1_danger(id: &str) -> Option<CapabilityDanger> {
    CAPABILITY_CATALOG
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.danger)
        .or_else(|| {
            matches!(
                id,
                "system:resources:unbounded"
                    | "net_bind"
                    | "uplink"
                    | "capsule:access:any"
                    | "authority:profile:manage"
                    | "authority:repair"
            )
            .then_some(CapabilityDanger::Extreme)
        })
}

fn revision_1_semantics(id: &str) -> Option<RevisionSemantics> {
    use AuthorityTargetKind::{
        AuditScope, CapsuleInstance, CapsulePackage, Credential, Group, Principal, System,
    };
    use CapabilityScope::{Global, Self_};

    let semantics = match id {
        "system:shutdown" => RevisionSemantics::new(Global, &[System], false, true),
        "system:status" => RevisionSemantics::new(Global, &[System], false, false),
        "capsule:install" => RevisionSemantics::new(Global, &[System, CapsulePackage], true, true),
        "self:capsule:install" => {
            RevisionSemantics::new(Self_, &[Principal, CapsulePackage], true, false)
        },
        "capsule:reload" | "capsule:remove" => {
            RevisionSemantics::new(Global, &[System, CapsuleInstance], true, true)
        },
        "self:capsule:reload"
        | "self:capsule:remove"
        | "self:workspace:promote"
        | "self:workspace:rollback" => {
            RevisionSemantics::new(Self_, &[Principal, CapsuleInstance], true, false)
        },
        "capsule:list" | "agent:list" | "group:list" | "invite:list" => {
            RevisionSemantics::new(Global, &[System], true, true)
        },
        "self:capsule:list"
        | "self:agent:list"
        | "self:group:list"
        | "self:quota:get"
        | "self:approval:respond" => RevisionSemantics::new(Self_, &[Principal], true, false),
        "agent:create" | "agent:create:clone" | "agent:modify" => {
            RevisionSemantics::new(Global, &[Principal, Group, CapsulePackage], true, true)
        },
        "agent:create:inherit"
        | "agent:delete"
        | "agent:enable"
        | "agent:disable"
        | "quota:set"
        | "quota:get"
        | "caps:grant"
        | "caps:revoke"
        | "caps:token:list" => RevisionSemantics::new(Global, &[Principal], true, true),
        "self:quota:set" => RevisionSemantics::new(Self_, &[Principal], true, true),
        "group:create" | "group:delete" | "group:modify" => {
            RevisionSemantics::new(Global, &[Group], true, true)
        },
        "caps:token:mint" | "caps:token:revoke" => {
            RevisionSemantics::new(Global, &[Principal, Credential], true, true)
        },
        "invite:issue" => RevisionSemantics::new(Global, &[Group, Credential], true, true),
        "invite:redeem" => {
            RevisionSemantics::new(Global, &[Principal, Group, Credential], false, true)
        },
        "invite:revoke" => RevisionSemantics::new(Global, &[Credential], true, true),
        "audit:read_all" => RevisionSemantics::new(Global, &[AuditScope], true, true),
        "self:auth:pair" => RevisionSemantics::new(Self_, &[Principal, Credential], true, true),
        "self:auth:pair:admin" => {
            RevisionSemantics::new(Self_, &[Principal, Credential], false, true)
        },
        "auth:pair:redeem" => RevisionSemantics::new(Global, &[Principal, Credential], false, true),
        "auth:pair" => RevisionSemantics::new(Global, &[Principal, Credential], true, true),
        "system:resources:unbounded" | "net_bind" | "uplink" => {
            RevisionSemantics::new(Self_, &[Principal, CapsuleInstance], false, true)
        },
        "capsule:access:any" => {
            RevisionSemantics::new(Self_, &[CapsulePackage, CapsuleInstance], false, true)
        },
        "authority:profile:manage" | "authority:repair" => {
            RevisionSemantics::new(Global, &[System, Principal, Group, Credential], false, true)
        },
        _ => return None,
    };
    Some(semantics)
}

impl RevisionSemantics {
    const fn new(
        scope: CapabilityScope,
        target_kinds: &'static [AuthorityTargetKind],
        delegable: bool,
        privileged: bool,
    ) -> Self {
        Self {
            scope,
            target_kinds,
            delegable,
            privileged,
        }
    }
}

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
    /// Borrow the wrapped digest storage.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

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
        validate_digest_length("capability entry", value.as_ref())?;
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
    /// Borrow the wrapped digest storage.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

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
        validate_digest_length("capability registry", value.as_ref())?;
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

/// BLAKE3 digest of a signed extension package that defines capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtensionPackageDigest<T = [u8; 32]>(T);

impl<T> ExtensionPackageDigest<T> {
    /// Borrow the wrapped digest storage.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return its storage.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsRef<[u8]>> ExtensionPackageDigest<T> {
    /// Validate and wrap digest storage.
    ///
    /// # Errors
    ///
    /// Returns an error unless the storage contains exactly 32 bytes.
    pub fn new(value: T) -> Result<Self, AuthorityRegistryError> {
        validate_digest_length("signed extension package", value.as_ref())?;
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

impl ExtensionPackageDigest {
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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum CapabilitySource {
    /// A capability defined by the Astrid host.
    Kernel,
    /// A capability supplied by a verified signed extension package.
    SignedExtension {
        /// BLAKE3 digest of the signed extension package.
        package_digest: ExtensionPackageDigest,
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
    schema_revision: CapabilityRegistryRevision,
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
        schema_revision: CapabilityRegistryRevision,
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
    pub const fn schema_revision(&self) -> CapabilityRegistryRevision {
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
#[non_exhaustive]
pub enum AuthorityRegistryError {
    /// A fixed capability ID has no authorization definition.
    #[error("capability-registry revision 1 entry {id:?} has no authorization definition")]
    MissingRevisionDefinition {
        /// Capability identifier.
        id: String,
    },
    /// A fixed capability ID has no danger classification.
    #[error("capability-registry revision 1 entry {id:?} has no display metadata")]
    MissingRevisionDisplayMetadata {
        /// Capability identifier.
        id: String,
    },
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
    schema_revision: CapabilityRegistryRevision,
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
            encode_bytes(output, package_digest.as_bytes());
        },
    }
}

#[cfg(test)]
mod tests;
