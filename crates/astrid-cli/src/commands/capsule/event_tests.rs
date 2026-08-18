use super::event::{EventAction, EventArgs, run};
use astrid_capsule_index::{
    ActorId, BuildProvenance, CanonicalSemVer, CapsuleName, Coordinate, Digest,
    EmbeddedPackageIdentity, GitObjectId, IndexId, IndexIdentity, MirrorUrl, Namespace,
    PublisherIdentity, RuntimeRequirements, SourceProvenance, TrustRootFingerprint,
};
use std::fs;

fn digest(seed: u8) -> Digest {
    Digest::blake3(&[seed; 3])
}

fn fixture_record(identity: &IndexIdentity) -> astrid_capsule_index::PublicationRecord {
    let coordinate = Coordinate::new(
        Namespace::new("demo").unwrap(),
        CapsuleName::new("demo").unwrap(),
    );
    let version = CanonicalSemVer::parse("1.0.0").unwrap();
    astrid_capsule_index::PublicationRecord::builder(
        identity.id.clone(),
        coordinate.clone(),
        version.clone(),
    )
    .artifact_locations(
        1,
        "application/vnd.astrid.capsule",
        vec![MirrorUrl::new("https://example.com/demo.capsule").unwrap()],
        digest(1),
    )
    .unwrap()
    .publisher(PublisherIdentity::new(
        ActorId::new("publisher").unwrap(),
        digest(2),
    ))
    .source(
        SourceProvenance::new(
            MirrorUrl::new("https://example.com/source").unwrap(),
            1,
            2,
            GitObjectId::new("a".repeat(40)).unwrap(),
            GitObjectId::new("b".repeat(40)).unwrap(),
            "v1.0.0",
            None,
            digest(3),
        )
        .unwrap(),
    )
    .runtime(RuntimeRequirements::new("astrid", "component-model-v1").unwrap())
    .package(EmbeddedPackageIdentity::new(coordinate, version, digest(4)))
    .manifest_digest(digest(5))
    .component_digest(digest(6))
    .wit_digest(digest(7))
    .capabilities(astrid_capsule_index::CapabilityClaims::new(Vec::new(), digest(8)).unwrap())
    .dependencies(astrid_capsule_index::DependencyClaims::new(Vec::new()).unwrap())
    .provenance(
        BuildProvenance::new(
            "https://slsa.dev/provenance/v1",
            digest(9),
            MirrorUrl::new("https://example.com/builder").unwrap(),
            "attestation",
        )
        .unwrap(),
    )
    .seal()
    .unwrap()
}

fn args(output_dir: &std::path::Path, identity: &IndexIdentity, action: EventAction) -> EventArgs {
    EventArgs {
        index_id: Some(identity.id.to_string()),
        index_base: Some("https://index.example".to_owned()),
        trust_root: Some(identity.trust_root.to_string()),
        index_source: None,
        namespace: "demo".to_owned(),
        name: "demo".to_owned(),
        version: "1.0.0".to_owned(),
        actor: "publisher".to_owned(),
        authorization_evidence: "evidence".to_owned(),
        authorization_signature_digest: digest(10).to_string(),
        recorded_at: "2026-01-01T00:00:00Z".to_owned(),
        output_dir: output_dir.to_owned(),
        dry_run: false,
        json: false,
        action,
    }
}

#[test]
fn event_preparation_is_idempotent_and_enforces_terminal_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let identity = IndexIdentity::new(
        IndexId::new("public").unwrap(),
        TrustRootFingerprint::new(digest(11)),
    );
    let release_dir = temp.path().join("records/demo/demo");
    fs::create_dir_all(&release_dir).unwrap();
    fs::write(
        release_dir.join("1.0.0.json"),
        serde_json::to_vec(&fixture_record(&identity)).unwrap(),
    )
    .unwrap();

    run(&args(
        temp.path(),
        &identity,
        EventAction::Yank {
            reason: Some("test".to_owned()),
        },
    ))
    .unwrap();
    let events_dir = temp.path().join("events");
    assert_eq!(fs::read_dir(&events_dir).unwrap().count(), 1);
    run(&args(
        temp.path(),
        &identity,
        EventAction::Yank {
            reason: Some("test".to_owned()),
        },
    ))
    .unwrap();
    assert_eq!(fs::read_dir(&events_dir).unwrap().count(), 1);
    run(&args(
        temp.path(),
        &identity,
        EventAction::AddMirror {
            mirror: "https://mirror.example/demo.capsule".to_owned(),
        },
    ))
    .unwrap();
    assert_eq!(fs::read_dir(&events_dir).unwrap().count(), 2);
    run(&args(
        temp.path(),
        &identity,
        EventAction::Tombstone {
            reason: "terminal".to_owned(),
        },
    ))
    .unwrap();
    assert!(
        run(&args(
            temp.path(),
            &identity,
            EventAction::Revoke {
                reason: "too late".to_owned(),
            },
        ))
        .is_err()
    );
}
