use super::*;
use crate::capability_grammar::{
    CAP_NET_BIND, CAP_RESOURCES_UNBOUNDED, CAP_UPLINK, CAPABILITY_CATALOG, KNOWN_CAPABILITIES_COUNT,
};

fn registered(
    id: &str,
    targets: impl IntoIterator<Item = AuthorityTargetKind>,
    delegable: bool,
    privileged: bool,
) -> RegisteredCapability {
    RegisteredCapability::new(
        ExactCapabilityId::new(id.to_string()).unwrap(),
        CapabilityScope::Global,
        targets,
        CapabilityDanger::Elevated,
        delegable,
        privileged,
        CapabilitySource::Kernel,
    )
    .unwrap()
}

#[test]
fn exact_capability_id_rejects_every_wildcard_position() {
    for value in ["*", "self:*", "a:*:b"] {
        assert!(matches!(
            ExactCapabilityId::new(value),
            Err(AuthorityRegistryError::WildcardCapabilityId { .. })
        ));
    }
    assert!(ExactCapabilityId::new("self:capsule:list").is_ok());
}

#[test]
fn migration_baseline_freezes_current_and_dormant_exact_ids() {
    let baseline = MIGRATION_BASELINE_CAPABILITY_IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(baseline.len(), MIGRATION_BASELINE_CAPABILITY_IDS.len());
    for id in &MIGRATION_BASELINE_CAPABILITY_IDS {
        ExactCapabilityId::new(*id).unwrap();
    }

    let catalog = CAPABILITY_CATALOG
        .iter()
        .map(|entry| entry.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(catalog.len(), KNOWN_CAPABILITIES_COUNT);
    assert!(catalog.is_subset(&baseline));

    let additions = baseline
        .difference(&catalog)
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        additions,
        BTreeSet::from([
            CAP_RESOURCES_UNBOUNDED,
            CAP_NET_BIND,
            CAP_UPLINK,
            "capsule:access:any",
            "authority:profile:manage",
            "authority:repair",
        ])
    );
}

#[test]
fn target_order_does_not_change_entry_digest() {
    let left = registered(
        "capsule:list",
        [
            AuthorityTargetKind::CapsuleInstance,
            AuthorityTargetKind::System,
        ],
        true,
        false,
    );
    let right = registered(
        "capsule:list",
        [
            AuthorityTargetKind::System,
            AuthorityTargetKind::CapsuleInstance,
        ],
        true,
        false,
    );
    assert_eq!(left.entry_digest(), right.entry_digest());
}

#[test]
fn every_authorization_field_changes_the_entry_digest() {
    let baseline = registered("capsule:list", [AuthorityTargetKind::System], true, false);
    let different_id = registered(
        "capsule:inspect",
        [AuthorityTargetKind::System],
        true,
        false,
    );
    let different_scope = RegisteredCapability::new(
        ExactCapabilityId::new("capsule:list".to_string()).unwrap(),
        CapabilityScope::Self_,
        [AuthorityTargetKind::System],
        CapabilityDanger::Elevated,
        true,
        false,
        CapabilitySource::Kernel,
    )
    .unwrap();
    let different_target = registered(
        "capsule:list",
        [AuthorityTargetKind::CapsuleInstance],
        true,
        false,
    );
    let nondelegable = registered("capsule:list", [AuthorityTargetKind::System], false, false);
    let privileged = registered("capsule:list", [AuthorityTargetKind::System], true, true);
    let extension = RegisteredCapability::new(
        ExactCapabilityId::new("capsule:list".to_string()).unwrap(),
        CapabilityScope::Global,
        [AuthorityTargetKind::System],
        CapabilityDanger::Elevated,
        true,
        false,
        CapabilitySource::SignedExtension {
            package_digest: [7; 32],
        },
    )
    .unwrap();
    let other_extension = RegisteredCapability::new(
        ExactCapabilityId::new("capsule:list".to_string()).unwrap(),
        CapabilityScope::Global,
        [AuthorityTargetKind::System],
        CapabilityDanger::Elevated,
        true,
        false,
        CapabilitySource::SignedExtension {
            package_digest: [8; 32],
        },
    )
    .unwrap();

    for changed in [
        different_id,
        different_scope,
        different_target,
        nondelegable,
        privileged,
        extension,
        other_extension,
    ] {
        assert_ne!(baseline.entry_digest(), changed.entry_digest());
    }
}

#[test]
fn danger_presentation_does_not_change_authority_identity() {
    let safe = RegisteredCapability::new(
        ExactCapabilityId::new("system:status".to_string()).unwrap(),
        CapabilityScope::Global,
        [AuthorityTargetKind::System],
        CapabilityDanger::Safe,
        true,
        false,
        CapabilitySource::Kernel,
    )
    .unwrap();
    let extreme = RegisteredCapability::new(
        ExactCapabilityId::new("system:status".to_string()).unwrap(),
        CapabilityScope::Global,
        [AuthorityTargetKind::System],
        CapabilityDanger::Extreme,
        true,
        false,
        CapabilitySource::Kernel,
    )
    .unwrap();

    assert_eq!(safe.entry_digest(), extreme.entry_digest());
    let revision = NonZeroU32::new(1).unwrap();
    let safe_manifest = CapabilityRegistryManifest::new(revision, [safe]).unwrap();
    let extreme_manifest = CapabilityRegistryManifest::new(revision, [extreme]).unwrap();
    assert_eq!(safe_manifest.digest(), extreme_manifest.digest());
}

#[test]
fn manifest_order_is_canonical_and_exact_refs_resolve() {
    let capsule = registered("capsule:list", [AuthorityTargetKind::System], true, false);
    let system = registered("system:status", [AuthorityTargetKind::System], true, false);
    let reference = capsule.capability_ref();
    let revision = NonZeroU32::new(1).unwrap();
    let left =
        CapabilityRegistryManifest::new(revision, [system.clone(), capsule.clone()]).unwrap();
    let right = CapabilityRegistryManifest::new(revision, [capsule.clone(), system]).unwrap();

    assert_eq!(left, right);
    assert_eq!(
        left.resolve(&reference)
            .map(RegisteredCapability::id)
            .map(ExactCapabilityId::as_str),
        Some(reference.id().as_str())
    );
    left.verify().unwrap();
}

#[test]
fn duplicate_content_bound_entries_fail_closed() {
    let entry = registered("system:status", [AuthorityTargetKind::System], true, false);
    assert!(matches!(
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), [entry.clone(), entry]),
        Err(AuthorityRegistryError::DuplicateCapabilityId { .. })
    ));
}

#[test]
fn resolution_requires_the_exact_digest() {
    let safe = registered("system:status", [AuthorityTargetKind::System], true, false);
    let safe_ref = safe.capability_ref();
    let owned_ref = CapabilityRef::new(
        ExactCapabilityId::new("system:status".to_string()).unwrap(),
        safe.entry_digest(),
    );
    let manifest =
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), [safe.clone()]).unwrap();
    let unknown = CapabilityRef::new(
        ExactCapabilityId::new("system:status".to_string()).unwrap(),
        CapabilityEntryDigest::from_array([0; 32]),
    );

    assert_eq!(
        manifest
            .resolve(&safe_ref)
            .map(RegisteredCapability::danger),
        Some(CapabilityDanger::Elevated)
    );
    assert_eq!(manifest.resolve(&owned_ref), Some(&safe));
    assert!(manifest.resolve(&unknown).is_none());
}

#[test]
fn digest_wrappers_reject_wrong_lengths() {
    assert!(matches!(
        CapabilityEntryDigest::new(&[0_u8; 31][..]),
        Err(AuthorityRegistryError::InvalidDigestLength { actual: 31, .. })
    ));
    assert!(matches!(
        CapabilityRegistryDigest::new(&[0_u8; 33][..]),
        Err(AuthorityRegistryError::InvalidDigestLength { actual: 33, .. })
    ));
    assert!(CapabilityEntryDigest::new(&[0_u8; 32]).is_ok());
    assert!(CapabilityRegistryDigest::new(&[0_u8; 32]).is_ok());
}

#[test]
fn empty_targets_and_registry_fail_closed() {
    assert!(matches!(
        RegisteredCapability::new(
            ExactCapabilityId::new("system:status".to_string()).unwrap(),
            CapabilityScope::Global,
            [],
            CapabilityDanger::Safe,
            true,
            false,
            CapabilitySource::Kernel,
        ),
        Err(AuthorityRegistryError::MissingTargetKind { .. })
    ));
    assert!(matches!(
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), []),
        Err(AuthorityRegistryError::EmptyRegistry)
    ));
}

#[test]
fn tampered_entry_and_manifest_digests_fail_closed() {
    let mut entry = registered("system:status", [AuthorityTargetKind::System], true, false);
    entry.delegable = false;
    assert!(matches!(
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), [entry]),
        Err(AuthorityRegistryError::EntryDigestMismatch { .. })
    ));

    let entry = registered("system:status", [AuthorityTargetKind::System], true, false);
    let mut manifest =
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), [entry]).unwrap();
    manifest.digest = CapabilityRegistryDigest::from_array([0; 32]);
    assert!(matches!(
        manifest.verify(),
        Err(AuthorityRegistryError::RegistryDigestMismatch { .. })
    ));
}

#[test]
fn same_id_with_different_authorization_semantics_fails_closed() {
    let delegable = registered("system:status", [AuthorityTargetKind::System], true, false);
    let direct_only = registered("system:status", [AuthorityTargetKind::System], false, false);

    assert_ne!(delegable.entry_digest(), direct_only.entry_digest());
    assert!(matches!(
        CapabilityRegistryManifest::new(NonZeroU32::new(1).unwrap(), [delegable, direct_only]),
        Err(AuthorityRegistryError::DuplicateCapabilityId { .. })
    ));
}

#[test]
fn registry_digests_have_golden_vectors() {
    let capsule = registered(
        "capsule:list",
        [
            AuthorityTargetKind::System,
            AuthorityTargetKind::CapsuleInstance,
        ],
        true,
        false,
    );
    assert_eq!(
        capsule.entry_digest().to_hex(),
        "908fee5f09e75ca149b93fd78de24340cef97d7ddeecd3d5d56fed3401f44195"
    );
    let manifest = CapabilityRegistryManifest::new(
        NonZeroU32::new(1).unwrap(),
        [
            capsule,
            registered("system:status", [AuthorityTargetKind::System], true, false),
        ],
    )
    .unwrap();
    assert_eq!(
        manifest.digest().to_hex(),
        "e61693befc8711222db7c91ecc44a1599f95ff3a16a4632f237c2d07545f7a88"
    );

    let next_revision = CapabilityRegistryManifest::new(
        NonZeroU32::new(2).unwrap(),
        manifest.entries().iter().cloned(),
    )
    .unwrap();
    assert_ne!(manifest.digest(), next_revision.digest());
}

#[test]
fn canonical_entry_bytes_are_stable() {
    let entry = registered(
        "capsule:list",
        [
            AuthorityTargetKind::CapsuleInstance,
            AuthorityTargetKind::System,
        ],
        true,
        false,
    );
    let mut encoded = Vec::new();
    encode_entry(
        &mut encoded,
        entry.id(),
        entry.scope(),
        entry.target_kinds(),
        entry.delegable(),
        entry.privileged(),
        entry.source(),
    );
    assert_eq!(
        hex::encode(encoded),
        "866c63617073756c653a6c69737401820005f5f48100"
    );
}

#[test]
fn canonical_unsigned_boundaries_use_shortest_forms() {
    let cases: &[(u64, &[u8])] = &[
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_535, &[0x19, 0xff, 0xff]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
    ];
    for (value, expected) in cases {
        let mut encoded = Vec::new();
        encode_unsigned(&mut encoded, *value);
        assert_eq!(&encoded, expected, "value {value}");
    }
}

#[test]
fn canonical_enum_and_source_tags_are_stable() {
    assert_eq!(scope_code(CapabilityScope::Self_), 0);
    assert_eq!(scope_code(CapabilityScope::Global), 1);
    assert_eq!(
        [
            AuthorityTargetKind::System,
            AuthorityTargetKind::Principal,
            AuthorityTargetKind::Group,
            AuthorityTargetKind::Credential,
            AuthorityTargetKind::CapsulePackage,
            AuthorityTargetKind::CapsuleInstance,
            AuthorityTargetKind::ApplicationSession,
            AuthorityTargetKind::Model,
            AuthorityTargetKind::AuditScope,
        ]
        .map(AuthorityTargetKind::code),
        [0, 1, 2, 3, 4, 5, 6, 7, 8]
    );

    let mut kernel = Vec::new();
    encode_source(&mut kernel, CapabilitySource::Kernel);
    assert_eq!(kernel, [0x81, 0x00]);

    let mut extension = Vec::new();
    encode_source(
        &mut extension,
        CapabilitySource::SignedExtension {
            package_digest: [7; 32],
        },
    );
    assert_eq!(&extension[..3], &[0x82, 0x01, 0x58]);
    assert_eq!(extension[3], 0x20);
    assert_eq!(&extension[4..], &[7; 32]);
}
