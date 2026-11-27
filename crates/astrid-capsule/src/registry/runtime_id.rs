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

#[path = "runtime_scope.rs"]
mod runtime_scope;
pub use runtime_scope::RuntimeScope;

impl RuntimeScope {
    /// Compare a pinned viewer to the instance owner. System residency has
    /// separate operator admission and an explicit principal view.
    #[must_use]
    pub fn matches_view_owner(&self, viewer: PrincipalUid) -> bool {
        let owner = match self {
            Self::Principal(uid) => Some(uid.as_bytes()),
            Self::SystemResident => None,
        };
        super::view_owner::matches(owner, viewer.as_bytes())
    }
}

/// Logical runtime slot identified by the capsule, artifact and authority scope.
pub type RuntimeKey = super::generation::RuntimeKey<CapsuleId, WasmHash, RuntimeScope>;

/// One incarnation of a logical runtime slot.
pub type RuntimeId = super::generation::RuntimeId<CapsuleId, WasmHash, RuntimeScope>;

#[cfg(test)]
impl RuntimeId {
    pub(crate) fn for_test(capsule_id: CapsuleId, generation: u64) -> Self {
        Self::for_test_scope(
            capsule_id,
            generation,
            RuntimeScope::Principal(PrincipalUid::from_bytes([generation as u8; 32])),
        )
    }

    pub(crate) fn for_test_scope(
        capsule_id: CapsuleId,
        generation: u64,
        scope: RuntimeScope,
    ) -> Self {
        super::generation::issue(
            &mut { generation },
            capsule_id,
            WasmHash::from_raw(format!("test-artifact-{generation}")),
            scope,
        )
        .expect("test runtime generation must be reservable")
    }
}

#[cfg(test)]
#[path = "issuance_tests.rs"]
mod issuance_tests;
