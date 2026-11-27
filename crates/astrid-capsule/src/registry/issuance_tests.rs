//! Exercise the same constructors and accessors used by runtime consumers.
use super::*;
use crate::registry::CapsuleRegistry;

#[test]
fn registry_issues_the_exact_key_and_last_available_generation() {
    let mut registry = CapsuleRegistry::new();
    registry.next_generation = u64::MAX - 2;
    for (generation, name, hash, scope) in [
        (
            u64::MAX - 2,
            "first",
            "artifact-a",
            RuntimeScope::Principal(PrincipalUid::from_bytes([17; 32])),
        ),
        (
            u64::MAX - 1,
            "second",
            "artifact-b",
            RuntimeScope::SystemResident,
        ),
    ] {
        let id = CapsuleId::new(name).unwrap();
        let artifact = WasmHash::from_raw(hash);
        let issued = registry
            .reserve_runtime_id(id.clone(), artifact.clone(), scope)
            .unwrap();
        assert_eq!(issued.key().capsule_id(), &id);
        assert_eq!(issued.key().artifact(), &artifact);
        assert_eq!(issued.key().scope(), scope);
        assert_eq!(issued.generation(), generation);
    }
    let refused = registry.reserve_runtime_id(
        CapsuleId::new("third").unwrap(),
        WasmHash::from_raw("artifact-c"),
        RuntimeScope::SystemResident,
    );
    assert!(refused.is_err());
    assert_eq!(registry.next_generation, u64::MAX);
}
