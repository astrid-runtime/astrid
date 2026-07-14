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

fn revision(value: u32) -> CapabilityRegistryRevision {
    CapabilityRegistryRevision::new(NonZeroU32::new(value).unwrap())
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
fn capability_registry_revision_1_freezes_current_and_dormant_exact_ids() {
    let baseline = CAPABILITY_REGISTRY_REVISION_1_IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(baseline.len(), CAPABILITY_REGISTRY_REVISION_1_IDS.len());
    for id in &CAPABILITY_REGISTRY_REVISION_1_IDS {
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
fn migration_baseline_registry_contains_every_fixed_definition() {
    let manifest = migration_baseline_registry().unwrap();
    let ids = manifest
        .entries()
        .iter()
        .map(|entry| entry.id().as_str())
        .collect::<BTreeSet<_>>();
    let expected = MIGRATION_BASELINE_CAPABILITY_IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    assert_eq!(
        manifest.schema_revision(),
        MIGRATION_BASELINE_SCHEMA_REVISION
    );
    assert_eq!(manifest.entries().len(), 51);
    assert_eq!(ids, expected);
    assert!(
        manifest
            .entries()
            .iter()
            .all(|entry| entry.source() == CapabilitySource::Kernel)
    );
    manifest.verify().unwrap();
}

#[test]
fn migration_baseline_preserves_catalog_scope_and_danger() {
    let manifest = migration_baseline_registry().unwrap();
    for catalog_entry in CAPABILITY_CATALOG {
        let registered = manifest
            .entries()
            .iter()
            .find(|entry| entry.id().as_str() == catalog_entry.id)
            .unwrap_or_else(|| panic!("missing catalog capability {}", catalog_entry.id));
        assert_eq!(
            registered.scope(),
            catalog_entry.scope,
            "{}",
            catalog_entry.id
        );
        assert_eq!(
            registered.danger(),
            catalog_entry.danger,
            "{}",
            catalog_entry.id
        );
    }

    for id in [
        CAP_RESOURCES_UNBOUNDED,
        CAP_NET_BIND,
        CAP_UPLINK,
        "capsule:access:any",
        "authority:profile:manage",
        "authority:repair",
    ] {
        let registered = manifest
            .entries()
            .iter()
            .find(|entry| entry.id().as_str() == id)
            .unwrap_or_else(|| panic!("missing baseline addition {id}"));
        assert_eq!(registered.danger(), CapabilityDanger::Extreme, "{id}");
    }
}

#[test]
fn migration_baseline_semantics_cover_sensitive_edges() {
    let manifest = migration_baseline_registry().unwrap();
    let entry = |id: &str| {
        manifest
            .entries()
            .iter()
            .find(|entry| entry.id().as_str() == id)
            .unwrap_or_else(|| panic!("missing baseline capability {id}"))
    };

    assert!(!entry("system:status").delegable());
    assert!(!entry("system:status").privileged());
    assert!(entry("self:auth:pair").delegable());
    assert!(entry("self:auth:pair").privileged());
    assert!(!entry("self:auth:pair:admin").delegable());
    assert!(!entry("capsule:access:any").delegable());
    assert!(entry("capsule:access:any").privileged());
    assert_eq!(
        entry("authority:repair").target_kinds(),
        &BTreeSet::from([
            AuthorityTargetKind::System,
            AuthorityTargetKind::Principal,
            AuthorityTargetKind::Group,
            AuthorityTargetKind::Credential,
        ])
    );
}

#[test]
fn migration_baseline_digest_vectors_are_stable() {
    let expected = [
        (
            "agent:create",
            "c9d1587351a1456f6e50f66d377560916a7f6f92d9d131d7024ad294628529cc",
        ),
        (
            "agent:create:clone",
            "eb43c11bb883dedcb5a3221a7d555c20df1ba05b7d8e5bae82a52943059d48f5",
        ),
        (
            "agent:create:inherit",
            "3591843cd8e4056cc0c18b29e69c1af40c9aa7deaf1c5732bbd4d5acbacc0d9a",
        ),
        (
            "agent:delete",
            "b50d4003730c3a4cd97ba0ad60c9e172d5d999d47c45e75a4671e0bb19e92af7",
        ),
        (
            "agent:disable",
            "76218ce076f9af7f55ca306140e59ddcf3addff4937898096d06b9fb01ddc169",
        ),
        (
            "agent:enable",
            "26d69fe48db627f94442f56a1cd1d648e12be670cdc50342fad7051adf82fe0e",
        ),
        (
            "agent:list",
            "b929c8c5e9867f4c8d3b9998ef03f38ef4247f2000f23ae5501871e3de0674db",
        ),
        (
            "agent:modify",
            "688a7b33ada935bc7d12e0bf7a4c062f6040cb6066c2bac3b16bf537129b31d8",
        ),
        (
            "audit:read_all",
            "0b8d39b03f848957d73ad0db00977e73e09da57f69a2680f30b26668a5885c1e",
        ),
        (
            "auth:pair",
            "17dd59e8d673908b9e65e9e1987ef6a956cb54ea52dd91391d39db6fb5c7a8c2",
        ),
        (
            "auth:pair:redeem",
            "755164d6481d3474ce244048c4c3b8d4f7e53e03476150334f61b62f39bd7963",
        ),
        (
            "authority:profile:manage",
            "ffe78ba8b48a775dbb344743463b60a5943c69ca764bb373e7111eb6c173f9a0",
        ),
        (
            "authority:repair",
            "1e1367b51221b5e2667c50aead762b871a1262decf3f90e8f449591912b0d848",
        ),
        (
            "caps:grant",
            "01655efea292a62b3656babf8d888abb1bf7752f40185a661a172633e2325823",
        ),
        (
            "caps:revoke",
            "76ceda7e4be1cc3bc52335d30851eb478e50adb766c1817075bc5f587c4da55a",
        ),
        (
            "caps:token:list",
            "176df3fd4672f24cbae46fbbca7999d9b0374019f93fc36136eecc6cb1a0991f",
        ),
        (
            "caps:token:mint",
            "ec9841e62d5833a1b163350e7b375f25d52bfe27623fc66aecc11c9d0a0f5f25",
        ),
        (
            "caps:token:revoke",
            "6b935504883624fa06e0a0ee97aa21c889424543a08cfc30230c5c71113f1cc2",
        ),
        (
            "capsule:access:any",
            "f9a5c447a08aa674999b32131b9ac560812f2dcfd479a426e84922ff2d52c710",
        ),
        (
            "capsule:install",
            "79eb65b1216c6edc719e107b91f5b33be0bb4865eb57f83fdb6df54cd936c6e5",
        ),
        (
            "capsule:list",
            "8eeb6a4ce2191d78c82dfd9598d44250af37cfe73ce80ce4c41f278688246409",
        ),
        (
            "capsule:reload",
            "d2b4ad2566218eb87d45cd9107d0ae45d282ffc97ec33ebc9a6b6ff03e93740f",
        ),
        (
            "capsule:remove",
            "70a45a0bbce7ea9da81e04360aba4e0f6c67ddc39ae42efe7484e2b19fa45d31",
        ),
        (
            "group:create",
            "d79da52e4033bf4e5febfcee1af9751c65a014fed1472f7b23e12420de5025ad",
        ),
        (
            "group:delete",
            "8a00eb4cd858515050cbcf58174c8294e769fb1d407c22ad6f941c949726a89f",
        ),
        (
            "group:list",
            "e93d376265c24fdbc39321ef86af19c7c719687d7ea12d568bf2684c13605fc4",
        ),
        (
            "group:modify",
            "a3957746717fce4f1922ae255a45ae16966fb54e8f9602b0106c6cbc41fa3e67",
        ),
        (
            "invite:issue",
            "dd6b1efec81f3183f82ae92dae8b3090bc22e5eb6eef6a071453c299a150574c",
        ),
        (
            "invite:list",
            "5d51573ee575411b1569cb738c1b26bac068ee78331947820de912f02d2d0ecc",
        ),
        (
            "invite:redeem",
            "bcf035e877441c90fee85e9fb67e17ca148f4f31d05542c13b580f4452ee4764",
        ),
        (
            "invite:revoke",
            "84f8a09710474578ca166aff32347aefb7e82cdfaafe495324cb7e3e48399faf",
        ),
        (
            "net_bind",
            "573c7e818405313d3d9adb625e8c0f31ab515be1895d229166e8cddca9060f23",
        ),
        (
            "quota:get",
            "b5af127b2ee4038daa9ee3069c3f6b808f6e9afd970ab0398b5e0b46e0d5e74e",
        ),
        (
            "quota:set",
            "4064cc54281dacf202f13bcf3313eb00eb441b556312fd42d9ec23b907bc40c3",
        ),
        (
            "self:agent:list",
            "70ada28d4c69802d4601d3031b294fa4cd4d462f715a3a64c14d40afa0a20c32",
        ),
        (
            "self:approval:respond",
            "fdac7a876ba95c7ba7c42cf1f4f5e3034dbcb3f07c865aa96b6894dd30ee7e9c",
        ),
        (
            "self:auth:pair",
            "965a89a82060415f1440a38947760f017660dfa7cba64c0dd5f80202ed740bb5",
        ),
        (
            "self:auth:pair:admin",
            "17171d102c5907748f961ffef6363267c79142ba277719f2eada06e8140b51fa",
        ),
        (
            "self:capsule:install",
            "04cede94f155ec402dde49baeb2a94b57c089768eb61ef691553863265770081",
        ),
        (
            "self:capsule:list",
            "a5c24d855d68c7b336f74176360bb66dac44affd352d97d54397c149ba8c247a",
        ),
        (
            "self:capsule:reload",
            "b6d260d5a5aea185ee8f04d751ad7e7392b753f24d42988698af0deb0b66e11a",
        ),
        (
            "self:capsule:remove",
            "2f50b2efdd603d2fad8aefc7a0cd785d67d29a07981afeec4c157101b58f9699",
        ),
        (
            "self:group:list",
            "d3a41e67d25c6a2b3c67f728ff03381bfef14432f3044807a1c9fc1185d5173b",
        ),
        (
            "self:quota:get",
            "909eb0ec2fdb481a756e5d367d665219ed742c64008a6b98ec7d1caeda3cf82f",
        ),
        (
            "self:quota:set",
            "0a49cae4d934a7e7cf797530e2c7c9a2dc6df7b6c1349484e497933466cccf9b",
        ),
        (
            "self:workspace:promote",
            "4ed985ebd2dd162f235f6667d7a847016b45ac9ea697a9f6c2c8762d3bf9b08e",
        ),
        (
            "self:workspace:rollback",
            "a826b1764a9e6069a55d9307e96a2cedc2a4fa9df5a8b349e914be29b996a896",
        ),
        (
            "system:resources:unbounded",
            "8c1ff06ff52166e4c21d44483bb6ba58d9d4b3c6356d411b88fa30b210c8a70f",
        ),
        (
            "system:shutdown",
            "88bb6671343b4cfafbe8cb8a0543fea47a9d45b214f06bde24a3a7d75a2e5cef",
        ),
        (
            "system:status",
            "fead56af90fd2681c504d8a87bfc630b7f2085552b81bff03d0bcdd22e70d9b3",
        ),
        (
            "uplink",
            "eb57220a6af0d3eaad2cebd5a6a242a44ddda25ff31bb5968c3861659493c66c",
        ),
    ];
    let manifest = migration_baseline_registry().unwrap();
    let actual = manifest
        .entries()
        .iter()
        .map(|entry| (entry.id().as_str(), entry.entry_digest().to_hex()))
        .collect::<Vec<_>>();

    assert_eq!(actual.len(), expected.len());
    for ((actual_id, actual_digest), (expected_id, expected_digest)) in actual.iter().zip(expected)
    {
        assert_eq!(*actual_id, expected_id);
        assert_eq!(actual_digest.as_str(), expected_digest, "{expected_id}");
    }
    assert_eq!(
        manifest.digest().to_hex(),
        "8acc9a0070c3787531b8000ab14d055003583e2c1d6256ab47186635a58a2b37"
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
            package_digest: ExtensionPackageDigest::from_array([7; 32]),
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
            package_digest: ExtensionPackageDigest::from_array([8; 32]),
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
    let revision = revision(1);
    let safe_manifest = CapabilityRegistryManifest::new(revision, [safe]).unwrap();
    let extreme_manifest = CapabilityRegistryManifest::new(revision, [extreme]).unwrap();
    assert_eq!(safe_manifest.digest(), extreme_manifest.digest());
}

#[test]
fn manifest_order_is_canonical_and_exact_refs_resolve() {
    let capsule = registered("capsule:list", [AuthorityTargetKind::System], true, false);
    let system = registered("system:status", [AuthorityTargetKind::System], true, false);
    let reference = capsule.capability_ref();
    let revision = revision(1);
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
        CapabilityRegistryManifest::new(revision(1), [entry.clone(), entry]),
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
    let manifest = CapabilityRegistryManifest::new(revision(1), [safe.clone()]).unwrap();
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
    assert!(matches!(
        ExtensionPackageDigest::new(&[0_u8; 30][..]),
        Err(AuthorityRegistryError::InvalidDigestLength { actual: 30, .. })
    ));
    assert!(CapabilityEntryDigest::new(&[0_u8; 32]).is_ok());
    assert!(CapabilityRegistryDigest::new(&[0_u8; 32]).is_ok());
    assert!(ExtensionPackageDigest::new(&[0_u8; 32]).is_ok());
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
        CapabilityRegistryManifest::new(revision(1), []),
        Err(AuthorityRegistryError::EmptyRegistry)
    ));
}

#[test]
fn tampered_entry_and_manifest_digests_fail_closed() {
    let mut entry = registered("system:status", [AuthorityTargetKind::System], true, false);
    entry.delegable = false;
    assert!(matches!(
        CapabilityRegistryManifest::new(revision(1), [entry]),
        Err(AuthorityRegistryError::EntryDigestMismatch { .. })
    ));

    let entry = registered("system:status", [AuthorityTargetKind::System], true, false);
    let mut manifest = CapabilityRegistryManifest::new(revision(1), [entry]).unwrap();
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
        CapabilityRegistryManifest::new(revision(1), [delegable, direct_only]),
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
        "f521ee33bd074ae2b608d5f415d8cc2567b1b2dba0a61b611518da0967b25253"
    );
    let manifest = CapabilityRegistryManifest::new(
        revision(1),
        [
            capsule,
            registered("system:status", [AuthorityTargetKind::System], true, false),
        ],
    )
    .unwrap();
    assert_eq!(
        manifest.digest().to_hex(),
        "82ce5c60e68fe848606aed138d81ac8f814623a7f8823e3e48989c2d8f872ddd"
    );

    let next_revision =
        CapabilityRegistryManifest::new(revision(2), manifest.entries().iter().cloned()).unwrap();
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
        (u64::from(u32::MAX), &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (
            u64::from(u32::MAX) + 1,
            &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
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
            package_digest: ExtensionPackageDigest::from_array([7; 32]),
        },
    );
    assert_eq!(&extension[..3], &[0x82, 0x01, 0x58]);
    assert_eq!(extension[3], 0x20);
    assert_eq!(&extension[4..], &[7; 32]);
}
