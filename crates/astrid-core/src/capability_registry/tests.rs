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
fn capability_registry_revision_1_contains_every_fixed_definition() {
    let manifest = capability_registry_revision_1().unwrap();
    let ids = manifest
        .entries()
        .iter()
        .map(|entry| entry.id().as_str())
        .collect::<BTreeSet<_>>();
    let expected = CAPABILITY_REGISTRY_REVISION_1_IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    assert_eq!(manifest.schema_revision(), CAPABILITY_REGISTRY_REVISION_1);
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
fn capability_registry_revision_1_preserves_catalog_scope_and_danger() {
    let manifest = capability_registry_revision_1().unwrap();
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
            .unwrap_or_else(|| panic!("missing revision 1 addition {id}"));
        assert_eq!(registered.danger(), CapabilityDanger::Extreme, "{id}");
    }
}

#[test]
fn capability_registry_revision_1_semantics_cover_sensitive_edges() {
    let manifest = capability_registry_revision_1().unwrap();
    let entry = |id: &str| {
        manifest
            .entries()
            .iter()
            .find(|entry| entry.id().as_str() == id)
            .unwrap_or_else(|| panic!("missing revision 1 capability {id}"))
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

const CAPABILITY_REGISTRY_REVISION_1_DIGESTS: &[(&str, &str)] = &[
    (
        "agent:create",
        "4e8a0890fe5a2cedd3dfdaa20329a54a28714541677290b0104ad649094ee58e",
    ),
    (
        "agent:create:clone",
        "0e68aaaa67c638ea41abd52a6c38e55dfffaaa98bd7a64c89a0c0f7d54d25b7e",
    ),
    (
        "agent:create:inherit",
        "7c6dc890286f51fc02f6294431007a7353a4454901f9bd05a638b0bb91f532a1",
    ),
    (
        "agent:delete",
        "50b16eb3103205b8a43b23c9570482ed0fb2ef6de0d7d4d4290aeb52b42fd0c9",
    ),
    (
        "agent:disable",
        "70f598abbde78c9fa59d7283204d3112ca90d575a8a1bb8e1e159c91b5b1ecf0",
    ),
    (
        "agent:enable",
        "f369036099ab2ff2f4970d95a6ab3652921c96f7f335e6817350d96b2950436d",
    ),
    (
        "agent:list",
        "e3288b4ff5930c8bb0dd5fb132424289d11245029521720933ee06b9d99a58be",
    ),
    (
        "agent:modify",
        "2f0b08cbbbb0608e13c41cec8e60d7569b44ab8ce67507261947e2a37d300ff7",
    ),
    (
        "audit:read_all",
        "d37700942d51a65ae02aef16edf6ab306d1814fe0845b52d2f07c76b19acd3de",
    ),
    (
        "auth:pair",
        "02d0db72af63a1bda4688296daa5979ca89148a3208d23641a0eafeb21c9691d",
    ),
    (
        "auth:pair:redeem",
        "ecf9c2e6c34b9f6d26bba43040febe57c955e53290ec17516a0ca97c22932dc4",
    ),
    (
        "authority:profile:manage",
        "f5647f9424ca66e8ad86b3bbc6cd69abe769bcfaeef0afdcf1dc32ec04e66d48",
    ),
    (
        "authority:repair",
        "fa83a7e2fe53adccdfb8f22ec76b16442ad348a821f91f200897385b873cc770",
    ),
    (
        "caps:grant",
        "ab418eaca028c77daee3cf24e603e2981249ba480605f9dad666abfa91d1d01f",
    ),
    (
        "caps:revoke",
        "12e19d80b91efad946ed33a3a75588e4f63b157a3f025a38450c3ec3e79a4970",
    ),
    (
        "caps:token:list",
        "bc57c6774958f6df5216d77153983462c59c89a7f21db693546bbf1ed2f7de20",
    ),
    (
        "caps:token:mint",
        "78e21ccbbe92d40efd26d8a4ae2dc9bdfb8ec3b9182a6182ebccd1477f6d11e5",
    ),
    (
        "caps:token:revoke",
        "2ed0188f7ab75bb99147848c25f8847021dd59ce40bf952c36490b50f136e9af",
    ),
    (
        "capsule:access:any",
        "c2e5c9eaac898896dc7c0a2bd39ad84ec7cfcc5555ddc50c0b5d8cdf981a1e18",
    ),
    (
        "capsule:install",
        "8c6934700efda9c3077c8f2b3cb5dbc563dad62421d0a4725a982c5e5686d878",
    ),
    (
        "capsule:list",
        "4a57fb6dba5592c6d0c7f046b8373fe99de315e82f783fdae86e6b99ebed1e09",
    ),
    (
        "capsule:reload",
        "2a8d975f2c82f0c510baf700352f38ad61aaa3244ad4341845a06184d38a6ae5",
    ),
    (
        "capsule:remove",
        "4758193d4d2aa4ec284792ee4de016aadd51ff28ff802e7bcbf684f68243edc2",
    ),
    (
        "group:create",
        "d8261e0b62963c7a75e47c73c7a8dfd71c898d55af212b7bbb7b1eedbfaccfbe",
    ),
    (
        "group:delete",
        "6c1d7bb11fcb15fcbdb5cc00892dc66b24b0721c83e2afb230fd6bd14632c9a8",
    ),
    (
        "group:list",
        "9a2e4502bc8b79b62eb7d0515486582ffb55d2e33ddd547706aebed0a209f3b9",
    ),
    (
        "group:modify",
        "906832c4748cdef984c2c20a066bb11614438c1197406c984fa3e18ba169f79c",
    ),
    (
        "invite:issue",
        "6304a695cf77a53846a66993940fd7fd5505aa71c65b92cb3fc003814e3eeac9",
    ),
    (
        "invite:list",
        "7f62b4b325d5a03b70b21f29ce5d3489d64e8d45572288e5b9c4ca2084b42f80",
    ),
    (
        "invite:redeem",
        "a6f9b37568ef8d649cbb1652408a640eac085d574313877a288aed1abe158d36",
    ),
    (
        "invite:revoke",
        "71bfda3067d8bdb9d70eef16381bbff69866329f3cf1fae7942cd82fa246e44e",
    ),
    (
        "net_bind",
        "de912396886486562595f29f9cdb9e4e86d7cade76aa50c2b99e997cd90852bf",
    ),
    (
        "quota:get",
        "9eafffe692d740029403f1cc4f1b997f00a30aacaa4248febde92794e899c575",
    ),
    (
        "quota:set",
        "83a27029dde977fc3075653552e5a53fd3e04566297ce6c7ac3ff12fce4c7fab",
    ),
    (
        "self:agent:list",
        "4ae3e25b7eb21956fceb73eee59d9304e9a0830397e55633216e08eebc5cfdfe",
    ),
    (
        "self:approval:respond",
        "2e225891a674aee4205da30f5bbc72454df1b5b24f978acec688ddde7950cfd8",
    ),
    (
        "self:auth:pair",
        "9ab37c94ad77fc70b34ad1283b4e254573fb73d068c064c365ca3828ae679cb0",
    ),
    (
        "self:auth:pair:admin",
        "5a4867fa2fc29d4e6607b149e92e2fcb83023f31962b4817f2b3b98ffc974469",
    ),
    (
        "self:capsule:install",
        "5383c1090fa3e204fc20f3c04d5b3acc3325566d9d49c91756af05353759c709",
    ),
    (
        "self:capsule:list",
        "c0880b629be8f453b9087a1d18f5820750e371e320f09fb7ece038117e3bd59c",
    ),
    (
        "self:capsule:reload",
        "3a0882f7d4969fd06ff42ef722062ddfee384a73e0cce2328045d5dc18384089",
    ),
    (
        "self:capsule:remove",
        "40da32931da6f54e2045c97c936c0a7cbb6e3c04a509b92e869b9adf6462dbeb",
    ),
    (
        "self:group:list",
        "e774470a69d80d46dfee25a4029a12f52bb4792e8802bc1309c589e69a484536",
    ),
    (
        "self:quota:get",
        "ca7311bb4622f366a71d12b33f1b3633a58bcd5af9c167a25cc2ba314d4dcbda",
    ),
    (
        "self:quota:set",
        "5cc56b5ba3c8232f2022b7730bb0a36ffd944dc0a7eb1eafe800c44ab7060944",
    ),
    (
        "self:workspace:promote",
        "c2e85a4b1738922a63d7be3f708982474dea52105e69ea4604d26cd0dee49cfc",
    ),
    (
        "self:workspace:rollback",
        "50817838952523b74ec779178cd6ac1ecaa9b649137e4fd09f1767f72f4520f0",
    ),
    (
        "system:resources:unbounded",
        "541ff0a36f55450dda506f8d07127e9ec585fd77a78d9895d1fe0d8befca7f91",
    ),
    (
        "system:shutdown",
        "b357447f17a3e8f5821542e96ccef03bb9ebe0be4cd55b57657e4eb8e0fefdc8",
    ),
    (
        "system:status",
        "86b76eb96e06c806d3599620f8af6e539407f7b667641fe40e52a35bfb752c6d",
    ),
    (
        "uplink",
        "89561b0ac228a3c5ef22b08059b4b832bd988b038e37cf548aa5d4c8fddceaf5",
    ),
];

#[test]
fn capability_registry_revision_1_digest_vectors_are_stable() {
    let manifest = capability_registry_revision_1().unwrap();
    let actual = manifest
        .entries()
        .iter()
        .map(|entry| (entry.id().as_str(), entry.entry_digest().to_hex()))
        .collect::<Vec<_>>();

    assert_eq!(actual.len(), CAPABILITY_REGISTRY_REVISION_1_DIGESTS.len());
    for ((actual_id, actual_digest), (expected_id, expected_digest)) in actual
        .iter()
        .zip(CAPABILITY_REGISTRY_REVISION_1_DIGESTS.iter().copied())
    {
        assert_eq!(*actual_id, expected_id);
        assert_eq!(actual_digest.as_str(), expected_digest, "{expected_id}");
    }
    assert_eq!(
        manifest.digest().to_hex(),
        "111cf3fe35104ccd25767d3f0b85778c0bb2561d10016f56ac868de4607940e6"
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
