use super::*;

#[test]
fn checked_descriptors_preserve_ids_and_refuse_conflicts() -> CapsuleResult<()> {
    let mut registry = CapsuleRegistry::new();
    let owner = CapsuleId::from_static("owner");
    let peer = CapsuleId::from_static("peer");
    let descriptor = UplinkDescriptor::builder("console", "cli").build();
    let id = descriptor.id;
    let registered = descriptor.registered_at;
    registry.register_uplink(&owner, descriptor.clone())?;

    assert!(matches!(
        CheckedSystemUplinks::new(&registry, &peer, vec![descriptor.clone()]),
        Err(CapsuleError::UnsupportedEntryPoint(_))
    ));
    assert!(matches!(
        CheckedSystemUplinks::new(
            &registry,
            &owner,
            vec![descriptor.clone(), descriptor.clone()]
        ),
        Err(CapsuleError::UnsupportedEntryPoint(_))
    ));
    let checked = CheckedSystemUplinks::new(&registry, &owner, vec![descriptor])?;
    assert_eq!(checked.0.len(), 1);
    assert_eq!(checked.0[0].id, id);
    assert_eq!(checked.0[0].registered_at, registered);
    assert_eq!(registry.uplinks.len(), 1);
    assert_eq!(registry.uplinks[&id].0, owner);
    Ok(())
}
