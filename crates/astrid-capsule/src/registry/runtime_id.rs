use astrid_core::PrincipalUid;

use crate::capsule::CapsuleId;

/// Content hash of one immutable capsule artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WasmHash(String);

impl WasmHash {
    #[must_use]
    pub fn from_raw(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    #[must_use]
    pub fn synthetic(name: &str, version: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"synthetic-capsule-instance:");
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(version.as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WasmHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Authority scope of one executable runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeScope {
    /// Mutable runtime state belongs exclusively to this durable principal.
    Principal(PrincipalUid),
    /// Explicit kernel service runtime with neutral host state.
    SystemResident,
}

/// Logical runtime slot. Artifact identity and authority identity are distinct.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeKey {
    capsule_id: CapsuleId,
    artifact: WasmHash,
    scope: RuntimeScope,
}

impl RuntimeKey {
    #[must_use]
    pub fn new(capsule_id: CapsuleId, artifact: WasmHash, scope: RuntimeScope) -> Self {
        Self {
            capsule_id,
            artifact,
            scope,
        }
    }

    #[must_use]
    pub fn capsule_id(&self) -> &CapsuleId {
        &self.capsule_id
    }

    #[must_use]
    pub fn artifact(&self) -> &WasmHash {
        &self.artifact
    }

    #[must_use]
    pub const fn scope(&self) -> RuntimeScope {
        self.scope
    }
}

/// One incarnation of a logical runtime slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeId {
    pub(super) key: RuntimeKey,
    pub(super) generation: u64,
}

impl RuntimeId {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn key(&self) -> &RuntimeKey {
        &self.key
    }

    #[cfg(test)]
    pub(crate) fn for_test(capsule_id: CapsuleId, generation: u64) -> Self {
        Self::for_test_scope(
            capsule_id,
            generation,
            RuntimeScope::Principal(PrincipalUid::from_bytes([generation as u8; 32])),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_scope(
        capsule_id: CapsuleId,
        generation: u64,
        scope: RuntimeScope,
    ) -> Self {
        Self {
            key: RuntimeKey::new(
                capsule_id,
                WasmHash::from_raw(format!("test-artifact-{generation}")),
                scope,
            ),
            generation,
        }
    }
}
