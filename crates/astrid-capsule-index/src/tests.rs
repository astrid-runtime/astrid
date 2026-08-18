use super::*;
use std::collections::BTreeMap;

fn digest(seed: u8) -> Digest {
    Digest::from_bytes(DigestAlgorithm::Blake3, [seed; 32]).unwrap()
}

fn identity() -> IndexIdentity {
    IndexIdentity::new(
        IndexId::new("astrid").unwrap(),
        TrustRootFingerprint::new(digest(9)),
    )
}

fn coordinate() -> Coordinate {
    "@official/demo-capsule".parse().unwrap()
}

fn source(seed: u8) -> SourceProvenance {
    SourceProvenance::new(
        MirrorUrl::new("https://github.com/astrid-runtime/demo").unwrap(),
        1,
        2,
        GitObjectId::new("a".repeat(40)).unwrap(),
        GitObjectId::new("b".repeat(40)).unwrap(),
        "v1.0.0",
        Some("capsule".to_owned()),
        digest(seed),
    )
    .unwrap()
}

fn provenance(seed: u8) -> BuildProvenance {
    BuildProvenance::new(
        "https://slsa.dev/provenance/v1",
        digest(seed),
        MirrorUrl::new("https://github.com/astrid-runtime/demo/actions").unwrap(),
        "attestation:demo",
    )
    .unwrap()
}

fn authorization(actor: &str, evidence: &str, seed: u8) -> EventAuthorization {
    EventAuthorization::new(ActorId::new(actor).unwrap(), evidence, digest(seed)).unwrap()
}

fn record(version: &str) -> PublicationRecord {
    let coordinate = coordinate();
    let version: CanonicalSemVer = version.parse().unwrap();
    let capabilities = CapabilityClaims::new_with_digests(
        vec![
            "ipc.publish:reply".to_owned(),
            "ipc.subscribe:request".to_owned(),
        ],
        digest(5),
        digest(6),
    )
    .unwrap();
    let dependencies = DependencyClaims::new_with_digest(Vec::new(), digest(7)).unwrap();
    let package = EmbeddedPackageIdentity::new(coordinate.clone(), version.clone(), digest(8));
    let mut metadata = BTreeMap::new();
    metadata.insert("a-key".to_owned(), "first".to_owned());
    metadata.insert("z-key".to_owned(), "last".to_owned());
    PublicationRecord::builder(identity().id.clone(), coordinate, version)
        .artifact_locations(
            42,
            "application/vnd.astrid.capsule",
            vec![MirrorUrl::new("https://github.com/astrid-runtime/demo/releases/v1.0.0").unwrap()],
            digest(1),
        )
        .unwrap()
        .publisher(PublisherIdentity::new(
            ActorId::new("publisher:demo").unwrap(),
            digest(2),
        ))
        .source(source(3))
        .runtime(
            RuntimeRequirements::new_with_digest("astrid", "wasm32-unknown-unknown", digest(4))
                .unwrap(),
        )
        .package(package)
        .manifest_digest(digest(10))
        .component_digest(digest(11))
        .wit_digest(digest(12))
        .capabilities(capabilities)
        .dependencies(dependencies)
        .provenance(provenance(13))
        .metadata(metadata)
        .seal()
        .unwrap()
}

fn input(record: &PublicationRecord) -> PublicationRecordInput {
    PublicationRecordInput {
        schema: record.schema().clone(),
        index_id: record.index_id().clone(),
        coordinate: record.coordinate().clone(),
        version: record.version().clone(),
        artifact: record.artifact().clone(),
        metadata: record.metadata().clone(),
        publisher: record.publisher().clone(),
        source: record.source().clone(),
        package: record.package().clone(),
        provenance: record.provenance().clone(),
    }
}

#[test]
fn names_reject_case_unicode_and_path_confusables() {
    for bad in [
        "",
        "Demo",
        "démo",
        "demo/name",
        "demo\\name",
        ".",
        "..",
        "demo%2f",
        "a.",
    ] {
        assert!(Namespace::new(bad).is_err(), "namespace accepted {bad:?}");
        assert!(CapsuleName::new(bad).is_err(), "name accepted {bad:?}");
    }
    assert!(Namespace::new("astrid").is_ok());
    assert!(CapsuleName::new("demo-capsule-2").is_ok());
    assert!("@astrid/demo-capsule-2".parse::<Coordinate>().is_ok());
    for bad in ["org/demo", "@org/demo/extra", "org/demo", "@/demo", "@org/"] {
        assert!(
            bad.parse::<Coordinate>().is_err(),
            "coordinate accepted {bad:?}"
        );
    }
}

#[test]
fn grouped_wire_golden_round_trips_with_sealed_digest() {
    let fixture = include_str!("../tests/fixtures/valid-publication.json");
    let publication: PublicationRecord = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        publication.publication_digest().to_string(),
        "blake3:7feede472ced5f17fc61ef0a4b1500aaf17c216c2402f58b082c0ccc773f4445"
    );
    assert_eq!(serde_json::to_string(&publication).unwrap(), fixture.trim());
    assert_eq!(publication.canonical_bytes(), {
        let round_trip: PublicationRecord = serde_json::from_str(fixture).unwrap();
        round_trip.canonical_bytes()
    });
}

#[test]
fn namespace_claim_and_transfer_require_three_bound_authorities() {
    let namespace = Namespace::new("community").unwrap();
    let claim = NamespaceClaim::new(
        namespace.clone(),
        ActorId::new("owner:old").unwrap(),
        "security@example.com",
        MirrorUrl::new("https://github.com/astrid-runtime/community").unwrap(),
        10,
        20,
        ActorId::new("sigstore:community").unwrap(),
        "Apache-2.0",
        None,
    )
    .unwrap();
    let mut ledger = IndexLedger::new(identity());
    ledger.register_namespace_claim(claim).unwrap();
    assert_eq!(
        ledger.namespace_owner(&namespace).unwrap().as_str(),
        "owner:old"
    );

    let transfer = NamespaceTransfer::new(
        namespace.clone(),
        ActorId::new("owner:old").unwrap(),
        ActorId::new("owner:new").unwrap(),
        authorization("owner:old", "outgoing:1", 21),
        authorization("owner:new", "incoming:1", 22),
        authorization("index:reviewer", "review:1", 23),
        1,
    )
    .unwrap();
    let envelope = EventEnvelope::new(
        SchemaVersion::event_v1(),
        identity(),
        1,
        "2026-01-01T00:00:00Z",
        ActorId::new("index:reviewer").unwrap(),
        authorization("index:reviewer", "review:1", 23),
        None,
        EventBody::NamespaceTransfer(transfer),
    )
    .unwrap();
    let encoded = serde_json::to_string(&envelope).unwrap();
    let decoded: EventEnvelope = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.canonical_bytes(), envelope.canonical_bytes());
    ledger.append_envelope(envelope).unwrap();
    assert_eq!(
        ledger.namespace_owner(&namespace).unwrap().as_str(),
        "owner:new"
    );

    let invalid_marker = NamespaceClaim::new(
        Namespace::new("community").unwrap(),
        ActorId::new("owner").unwrap(),
        "security@example.com",
        MirrorUrl::new("https://github.com/astrid-runtime/community").unwrap(),
        1,
        2,
        ActorId::new("sigstore:community").unwrap(),
        "MIT",
        Some(IndexId::new("astrid").unwrap()),
    );
    assert!(invalid_marker.is_err());
}

#[test]
fn event_envelopes_enforce_sequence_chain_replay_and_actor_binding() {
    let publication = record("1.0.0");
    let key = publication.key();
    let mut ledger = IndexLedger::new(identity());
    ledger.publish(publication).unwrap();
    let actor = ActorId::new("maintainer").unwrap();
    let first = EventEnvelope::new(
        SchemaVersion::event_v1(),
        identity(),
        1,
        "2026-01-01T00:00:00.123000Z",
        actor.clone(),
        authorization("maintainer", "event:1", 31),
        None,
        EventBody::Publication(IndexEvent::yank(actor.clone(), key.clone(), None)),
    )
    .unwrap();
    assert_eq!(first.recorded_at(), "2026-01-01T00:00:00.123Z");
    ledger.append_envelope(first.clone()).unwrap();
    assert!(
        ledger.append_envelope(first.clone()).is_err(),
        "replay must fail"
    );

    let gap = EventEnvelope::new(
        SchemaVersion::event_v1(),
        identity(),
        3,
        "2026-01-01T00:00:01Z",
        actor.clone(),
        authorization("maintainer", "event:3", 32),
        Some(first.event_digest().clone()),
        EventBody::Publication(IndexEvent::unyank(actor.clone(), key.clone())),
    )
    .unwrap();
    assert!(
        ledger.append_envelope(gap).is_err(),
        "sequence gap must fail"
    );

    let retarget = EventEnvelope::new(
        SchemaVersion::event_v1(),
        identity(),
        2,
        "2026-01-01T00:00:01Z",
        actor.clone(),
        authorization("maintainer", "event:2", 33),
        Some(first.event_digest().clone()),
        EventBody::Publication(IndexEvent::unyank(
            actor.clone(),
            PublicationKey::new(
                identity().id.clone(),
                "@official/other-capsule".parse().unwrap(),
                "1.0.0".parse().unwrap(),
            ),
        )),
    )
    .unwrap();
    assert!(
        ledger.append_envelope(retarget).is_err(),
        "retarget must fail"
    );

    assert!(EventAuthorization::new(actor.clone(), "", digest(34)).is_err());
    assert!(
        EventEnvelope::new(
            SchemaVersion::event_v1(),
            identity(),
            2,
            "2026-01-01T00:00:01Z",
            ActorId::new("different").unwrap(),
            authorization("maintainer", "event:2", 35),
            Some(first.event_digest().clone()),
            EventBody::Publication(IndexEvent::unyank(actor, key)),
        )
        .is_err()
    );
}

#[test]
fn semver_is_canonical_and_has_no_build_metadata() {
    let version: CanonicalSemVer = "1.2.3-alpha.1".parse().unwrap();
    assert_eq!(version.to_string(), "1.2.3-alpha.1");
    assert!("1.2.3+local".parse::<CanonicalSemVer>().is_err());
    assert!("1.2".parse::<CanonicalSemVer>().is_err());
    assert!("v1.2.3".parse::<CanonicalSemVer>().is_err());
    assert!("1.2.3-01".parse::<CanonicalSemVer>().is_err());
}

#[test]
fn digests_require_algorithm_and_lowercase_exact_length() {
    let valid = format!("sha256:{}", "ab".repeat(32));
    assert_eq!(Digest::parse(&valid).unwrap().to_string(), valid);
    for invalid in [
        "sha256:AB00000000000000000000000000000000000000000000000000000000000000",
        "sha256:ab",
        "SHA256:ab00000000000000000000000000000000000000000000000000000000000000",
        "sha256-ab00000000000000000000000000000000000000000000000000000000000000",
        "unknown:ab00000000000000000000000000000000000000000000000000000000000000",
    ] {
        assert!(Digest::parse(invalid).is_err(), "accepted {invalid}");
    }
    assert!(TrustRootFingerprint::parse(&"ab".repeat(32)).is_ok());
}

#[test]
fn typed_required_fields_and_url_invariants_are_enforced() {
    assert!(MirrorUrl::new("https://user@example.com/a").is_err());
    assert!(MirrorUrl::new("https://example.com:443/a").is_err());
    assert!(MirrorUrl::new("https://example.com/a?token=x").is_err());
    assert!(MirrorUrl::new("https://example.com/a#fragment").is_err());
    assert!(MirrorUrl::new("https://example.com/a%20b").is_err());
    assert!(MirrorUrl::new("https://example.com/a/./b").is_err());
    assert!(MirrorUrl::new("https://example.com/a/../b").is_err());
    assert!(serde_json::from_str::<MirrorUrl>("\"https://example.com/a/../b\"").is_err());
    assert!(serde_json::from_str::<GitObjectId>(&format!("\"{}\"", "A".repeat(40))).is_err());
    assert!(serde_json::from_str::<ActorId>("\"\"").is_err());
    assert!(
        SourceProvenance::new(
            MirrorUrl::new("https://example.com").unwrap(),
            0,
            2,
            GitObjectId::new("a".repeat(40)).unwrap(),
            GitObjectId::new("b".repeat(40)).unwrap(),
            "v1",
            None,
            digest(1),
        )
        .is_err()
    );
    assert!(
        PublicationRecord::builder(
            identity().id.clone(),
            coordinate(),
            "1.0.0".parse().unwrap(),
        )
        .seal()
        .is_err()
    );
}

#[test]
fn unsupported_schema_versions_fail_closed() {
    let publication = record("1.0.0");
    let mut publication_input = input(&publication);
    publication_input.schema = SchemaVersion::new("publication-v2").unwrap();
    assert!(PublicationRecord::seal(publication_input).is_err());

    let actor = ActorId::new("maintainer").unwrap();
    let event = EventBody::Publication(IndexEvent::yank(actor.clone(), publication.key(), None));
    assert!(
        EventEnvelope::new(
            SchemaVersion::new("event-envelope-v9").unwrap(),
            identity(),
            1,
            "2026-01-01T00:00:00Z",
            actor,
            authorization("maintainer", "event:1", 40),
            None,
            event,
        )
        .is_err()
    );
}

#[test]
fn canonical_serialization_is_field_order_independent_and_domain_separated() {
    let left = record("1.0.0");
    let mut right_input = input(&left);
    right_input.metadata = [
        ("z-key".to_owned(), "last".to_owned()),
        ("a-key".to_owned(), "first".to_owned()),
    ]
    .into_iter()
    .collect();
    let right = PublicationRecord::seal(right_input).unwrap();
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    assert_eq!(left.publication_digest(), right.publication_digest());
    assert_ne!(
        left.publication_digest(),
        &Digest::blake3(&left.canonical_bytes())
    );
}

#[test]
fn same_coordinate_is_idempotent_or_equivocation() {
    let one = record("1.0.0");
    assert_eq!(one.classify_against(None), PublicationClassification::New);
    assert_eq!(
        one.classify_against(Some(&one)),
        PublicationClassification::Idempotent
    );
    let mut changed_input = input(&one);
    changed_input.package.manifest_digest = digest(99);
    let changed = PublicationRecord::seal(changed_input).unwrap();
    assert_eq!(
        one.classify_against(Some(&changed)),
        PublicationClassification::Equivocation
    );
    let mut other_input = input(&one);
    other_input.index_id = IndexId::new("aos").unwrap();
    let other_index = PublicationRecord::seal(other_input).unwrap();
    assert_ne!(one.key(), other_index.key());
}

#[test]
fn lifecycle_and_append_only_name_non_reuse() {
    let first = record("1.0.0");
    let key = first.key();
    let mut ledger = IndexLedger::new(identity());
    assert_eq!(
        ledger.publish(first.clone()).unwrap(),
        PublicationClassification::New
    );
    assert_eq!(
        ledger.publish(first.clone()).unwrap(),
        PublicationClassification::Idempotent
    );
    ledger
        .append_event(IndexEvent::yank(
            ActorId::new("maintainer").unwrap(),
            key.clone(),
            None,
        ))
        .unwrap();
    ledger
        .append_event(IndexEvent::unyank(
            ActorId::new("maintainer").unwrap(),
            key.clone(),
        ))
        .unwrap();
    ledger
        .append_event(IndexEvent::deprecate(
            ActorId::new("maintainer").unwrap(),
            key.clone(),
            None,
            Some("use next".to_owned()),
        ))
        .unwrap();
    assert!(ledger.lifecycle(&key).unwrap().is_deprecated());
    ledger
        .append_event(IndexEvent::tombstone(
            ActorId::new("maintainer").unwrap(),
            key.clone(),
            "legal request".to_owned(),
        ))
        .unwrap();
    assert!(ledger.lifecycle(&key).unwrap().is_tombstoned());
    assert!(
        ledger
            .append_event(IndexEvent::unyank(ActorId::new("maintainer").unwrap(), key,))
            .is_err()
    );
}

#[test]
fn resolver_excludes_yanked_and_prerelease_but_preserves_lock() {
    let stable = record("1.0.0");
    let newer = record("2.0.0");
    let pre = record("3.0.0-alpha.1");
    let records = vec![stable.clone(), newer.clone(), pre.clone()];
    let events = vec![IndexEvent::yank(
        ActorId::new("maintainer").unwrap(),
        newer.key(),
        None,
    )];
    let resolver = Resolver::new(identity(), &records, &events);
    let selected = resolver
        .resolve(&coordinate(), &VersionReq::parse(">=1.0.0").unwrap())
        .unwrap();
    assert_eq!(selected.record.version().to_string(), "1.0.0");
    let pre_req = VersionReq::parse(">=3.0.0-alpha.1").unwrap();
    assert_eq!(
        resolver
            .resolve(&coordinate(), &pre_req)
            .unwrap()
            .record
            .version()
            .to_string(),
        "3.0.0-alpha.1"
    );
    let lock = LockRecord::from_publication(&identity(), &newer);
    assert!(
        resolver
            .resolve_with_lock(&coordinate(), &VersionReq::parse("^2").unwrap(), &lock)
            .unwrap()
            .state
            .is_yanked()
    );
    let revoked_events = vec![
        events[0].clone(),
        IndexEvent::revoke(
            ActorId::new("security").unwrap(),
            newer.key(),
            "compromised".to_owned(),
        ),
    ];
    let revoked_resolver = Resolver::new(identity(), &records, &revoked_events);
    assert!(matches!(
        revoked_resolver.resolve_with_lock(&coordinate(), &VersionReq::parse("^2").unwrap(), &lock),
        Err(IndexError::LockedPublicationRevoked(_))
    ));
}

#[test]
fn lock_binds_index_root_and_all_content_digests() {
    let publication = record("1.0.0");
    let lock = LockRecord::from_publication(&identity(), &publication);
    lock.verify(&identity(), &publication).unwrap();
    let other_identity = IndexIdentity::new(
        IndexId::new("other").unwrap(),
        identity().trust_root.clone(),
    );
    assert!(matches!(
        lock.verify(&other_identity, &publication),
        Err(IndexError::LockIndexMismatch)
    ));
}
