//! Private-state domain types and the bounded canonical manifest model.

use crate::error::GenerationError;

pub const MAGIC: &[u8; 8] = b"ASTRIDSG";
pub const VERSION: u8 = 1;
pub const DOMAIN: &[u8] = b"astrid.system-generation.manifest.v1";
pub const DIGEST_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const COMPONENT_BYTES: usize = 256;
pub const MAX_COMPONENTS: usize = COMPONENT_BYTES / DIGEST_LEN;
pub const FIXED_PREFIX_LEN: usize = 8 + 1 + 1 + 1 + 1;
pub const UNSIGNED_LEN: usize =
    FIXED_PREFIX_LEN + (DIGEST_LEN * 4) + COMPONENT_BYTES + 8 + 8 + 8 + (8 * 4);
pub const SIGNER_OFFSET: usize = UNSIGNED_LEN;
pub const SIGNATURE_OFFSET: usize = SIGNER_OFFSET + KEY_LEN;
pub const MANIFEST_LEN: usize = SIGNATURE_OFFSET + SIGNATURE_LEN;
pub const REVOKED_FLAG: u8 = 1;

const MANIFEST_IDENTITY_DOMAIN: &str = "astrid.system-generation.manifest-identity.v1";

/// A non-zero domain-separated BLAKE3 content identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentId([u8; DIGEST_LEN]);

impl ContentId {
    pub fn from_payload(payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("astrid.system-generation.content-id.v1");
        hasher.update(payload);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn try_from_bytes(bytes: [u8; DIGEST_LEN]) -> Result<Self, GenerationError> {
        if is_zero(&bytes) {
            return Err(GenerationError::InvalidContentId);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

/// The identity of a verified canonical signed manifest.
///
/// The field is intentionally private and the only constructor is the
/// verifier-owned canonical-byte path. Callers may compare or copy an
/// identity, but cannot mint one for an unverified manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestIdentity([u8; DIGEST_LEN]);

impl ManifestIdentity {
    pub(crate) fn from_canonical(bytes: &[u8; MANIFEST_LEN]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(MANIFEST_IDENTITY_DOMAIN);
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }

    pub const fn as_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

/// A monotonic generation number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(u64);

impl Generation {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A rollback floor carried by a signed generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RollbackFloor(u64);

impl RollbackFloor {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An expiry timestamp in Unix seconds. Zero means no expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Expiration(u64);

impl Expiration {
    pub const fn never() -> Self {
        Self(0)
    }

    pub const fn at(unix_seconds: u64) -> Self {
        Self(unix_seconds)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn is_expired(self, now: u64) -> bool {
        self.0 != 0 && now >= self.0
    }
}

/// Signed revocation metadata. Revoked generations are never admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    Active,
    Revoked,
}

impl Revocation {
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// Byte sizes bound to the generation's measured artifacts and CAS closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestSizes {
    kernel_bytes: u64,
    plan_bytes: u64,
    object_bytes: u64,
    closure_bytes: u64,
}

/// Inert input DTO for constructing a manifest. It is validated by `try_new`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestInput {
    pub kernel_identity: ContentId,
    pub plan_digest: ContentId,
    pub components: ComponentSet,
    pub object_root: ContentId,
    pub closure_root: ContentId,
    pub generation: Generation,
    pub rollback_floor: RollbackFloor,
    pub expires_at: Expiration,
    pub revocation: Revocation,
    pub sizes: ManifestSizes,
}

impl ManifestSizes {
    pub const fn new(
        kernel_bytes: u64,
        plan_bytes: u64,
        object_bytes: u64,
        closure_bytes: u64,
    ) -> Self {
        Self {
            kernel_bytes,
            plan_bytes,
            object_bytes,
            closure_bytes,
        }
    }

    pub const fn kernel_bytes(self) -> u64 {
        self.kernel_bytes
    }

    pub const fn plan_bytes(self) -> u64 {
        self.plan_bytes
    }

    pub const fn object_bytes(self) -> u64 {
        self.object_bytes
    }

    pub const fn closure_bytes(self) -> u64 {
        self.closure_bytes
    }
}

/// A sorted, duplicate-free, fixed-capacity component digest set.
///
/// The 256-byte wire slot derives `MAX_COMPONENTS` from the digest width;
/// this is a protocol/DoS ceiling, not an operator knob. Unused slots are
/// required to be zero during decoding and never become authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentSet {
    count: u8,
    digests: [u8; COMPONENT_BYTES],
}

impl ComponentSet {
    pub const fn empty() -> Self {
        Self {
            count: 0,
            digests: [0; COMPONENT_BYTES],
        }
    }

    pub fn try_from_slice(values: &[ContentId]) -> Result<Self, GenerationError> {
        if values.len() > MAX_COMPONENTS {
            return Err(GenerationError::InvalidComponentSet);
        }
        let mut out = Self::empty();
        let mut index = 0;
        while index < values.len() {
            if index != 0 && values[index - 1] >= values[index] {
                return Err(GenerationError::InvalidComponentSet);
            }
            let bytes = values[index].as_bytes();
            let start = index * DIGEST_LEN;
            out.digests[start..start + DIGEST_LEN].copy_from_slice(&bytes);
            index += 1;
        }
        out.count = values.len() as u8;
        Ok(out)
    }

    pub const fn count(self) -> usize {
        self.count as usize
    }

    pub fn digest(self, index: usize) -> Option<ContentId> {
        if index >= self.count() {
            return None;
        }
        let start = index * DIGEST_LEN;
        let mut bytes = [0u8; DIGEST_LEN];
        bytes.copy_from_slice(&self.digests[start..start + DIGEST_LEN]);
        Some(ContentId(bytes))
    }

    pub(crate) const fn count_byte(self) -> u8 {
        self.count
    }

    pub(crate) fn raw_bytes(self) -> [u8; COMPONENT_BYTES] {
        self.digests
    }

    pub(crate) fn from_raw(
        count: u8,
        digests: [u8; COMPONENT_BYTES],
    ) -> Result<Self, GenerationError> {
        if count as usize > MAX_COMPONENTS {
            return Err(GenerationError::InvalidComponentSet);
        }
        let set = Self { count, digests };
        let mut index = 0;
        while index < MAX_COMPONENTS {
            let start = index * DIGEST_LEN;
            let mut bytes = [0u8; DIGEST_LEN];
            bytes.copy_from_slice(&set.digests[start..start + DIGEST_LEN]);
            if index < count as usize {
                let id = ContentId::try_from_bytes(bytes)?;
                if index != 0 {
                    let previous = set
                        .digest(index - 1)
                        .ok_or(GenerationError::InvalidComponentSet)?;
                    if previous >= id {
                        return Err(GenerationError::InvalidComponentSet);
                    }
                }
            } else if !is_zero(&bytes) {
                return Err(GenerationError::InvalidComponentSet);
            }
            index += 1;
        }
        Ok(set)
    }
}

/// The authority-bearing content and policy description for one generation.
/// No slot label, host path, or deployment location is representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemGenerationManifest {
    kernel_identity: ContentId,
    plan_digest: ContentId,
    components: ComponentSet,
    object_root: ContentId,
    closure_root: ContentId,
    generation: Generation,
    rollback_floor: RollbackFloor,
    expires_at: Expiration,
    revocation: Revocation,
    sizes: ManifestSizes,
}

impl SystemGenerationManifest {
    pub fn try_new(input: ManifestInput) -> Result<Self, GenerationError> {
        if input.rollback_floor.get() > input.generation.get() {
            return Err(GenerationError::InvalidFloor);
        }
        Ok(Self {
            kernel_identity: input.kernel_identity,
            plan_digest: input.plan_digest,
            components: input.components,
            object_root: input.object_root,
            closure_root: input.closure_root,
            generation: input.generation,
            rollback_floor: input.rollback_floor,
            expires_at: input.expires_at,
            revocation: input.revocation,
            sizes: input.sizes,
        })
    }

    pub const fn kernel_identity(self) -> ContentId {
        self.kernel_identity
    }

    pub const fn plan_digest(self) -> ContentId {
        self.plan_digest
    }

    pub const fn components(self) -> ComponentSet {
        self.components
    }

    pub const fn object_root(self) -> ContentId {
        self.object_root
    }

    pub const fn closure_root(self) -> ContentId {
        self.closure_root
    }

    pub const fn generation(self) -> Generation {
        self.generation
    }

    pub const fn rollback_floor(self) -> RollbackFloor {
        self.rollback_floor
    }

    pub const fn expires_at(self) -> Expiration {
        self.expires_at
    }

    pub const fn revocation(self) -> Revocation {
        self.revocation
    }

    pub const fn sizes(self) -> ManifestSizes {
        self.sizes
    }
}

/// The signed envelope decoded from the fixed wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignedSystemGeneration {
    pub(crate) manifest: SystemGenerationManifest,
    pub(crate) signer: [u8; KEY_LEN],
    pub(crate) signature: [u8; SIGNATURE_LEN],
}

impl SignedSystemGeneration {
    pub(crate) const fn manifest(self) -> SystemGenerationManifest {
        self.manifest
    }

    pub(crate) const fn signer(self) -> [u8; KEY_LEN] {
        self.signer
    }
}

fn is_zero(bytes: &[u8; DIGEST_LEN]) -> bool {
    let mut index = 0;
    while index < DIGEST_LEN {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}
