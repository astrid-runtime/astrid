use super::*;
use astrid_capsule_index::{
    BuildProvenance, CapabilityClaims, DependencyClaims, DigestAlgorithm, EmbeddedPackageIdentity,
    GitObjectId, IndexId, MirrorUrl, PublisherIdentity, RuntimeRequirements, SourceProvenance,
};
use astrid_capsule_index_tuf::{
    MemoryTransport, TrustConfig, root_fingerprint_from_bytes, sparse_object_path,
};
use ed25519_dalek::{Signer, SigningKey};
use olpc_cjson::CanonicalFormatter;
use semver::VersionReq;
use serde_json::{Value, json};
use sha2::Digest as Sha2Digest;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::tempdir;
use url::Url;

const EXPIRES: &str = "2999-01-01T00:00:00Z";

fn digest(seed: u8) -> Digest {
    Digest::from_bytes(DigestAlgorithm::Blake3, [seed; 32]).unwrap()
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut bytes, CanonicalFormatter::new());
    value.serialize(&mut serializer).unwrap();
    bytes
}

fn key_object(key: &SigningKey) -> Value {
    json!({
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": { "public": hex::encode(key.verifying_key().to_bytes()) }
    })
}

fn key_id(key: &SigningKey) -> String {
    hex::encode(sha2::Sha256::digest(canonical(&key_object(key))))
}

fn signed(role: &Value, key: &SigningKey) -> Vec<u8> {
    let message = canonical(role);
    serde_json::to_vec(&json!({
        "signed": role,
        "signatures": [{
            "keyid": key_id(key),
            "sig": hex::encode(key.sign(&message).to_bytes())
        }]
    }))
    .unwrap()
}

fn root_version(key: &SigningKey, version: u64) -> Vec<u8> {
    let id = key_id(key);
    signed(
        &json!({
            "_type": "root",
            "spec_version": "1.0.0",
            "consistent_snapshot": true,
            "version": version,
            "expires": EXPIRES,
            "keys": { id.clone(): key_object(key) },
            "roles": {
                "root": { "keyids": [id.clone()], "threshold": 1 },
                "snapshot": { "keyids": [id.clone()], "threshold": 1 },
                "targets": { "keyids": [id.clone()], "threshold": 1 },
                "timestamp": { "keyids": [id], "threshold": 1 }
            }
        }),
        key,
    )
}

fn root(key: &SigningKey) -> Vec<u8> {
    root_version(key, 1)
}

fn record(index_id: &str, version: &str) -> PublicationRecord {
    let index_id: IndexId = index_id.parse().unwrap();
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let version: CanonicalSemVer = version.parse().unwrap();
    let capabilities = CapabilityClaims::new_with_digests(
        vec!["ipc.publish:reply".to_owned()],
        digest(5),
        digest(6),
    )
    .unwrap();
    let dependencies = DependencyClaims::new_with_digest(Vec::new(), digest(7)).unwrap();
    let package_identity =
        EmbeddedPackageIdentity::new(coordinate.clone(), version.clone(), digest(8));
    PublicationRecord::builder(index_id, coordinate, version)
        .artifact_locations(
            42,
            "application/vnd.astrid.capsule",
            vec![MirrorUrl::new("https://example.com/capsule").unwrap()],
            digest(1),
        )
        .unwrap()
        .publisher(PublisherIdentity::new(
            ActorId::new("publisher:test").unwrap(),
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
        .runtime(
            RuntimeRequirements::new_with_digest("astrid", "wasm32-unknown-unknown", digest(4))
                .unwrap(),
        )
        .package(package_identity)
        .manifest_digest(digest(10))
        .component_digest(digest(11))
        .wit_digest(digest(12))
        .capabilities(capabilities)
        .dependencies(dependencies)
        .provenance(
            BuildProvenance::new(
                "https://slsa.dev/provenance/v1",
                digest(13),
                MirrorUrl::new("https://example.com/builder").unwrap(),
                "attestation:test",
            )
            .unwrap(),
        )
        .seal()
        .unwrap()
}

#[derive(Debug)]
struct Fixture {
    identity: IndexIdentity,
    record: PublicationRecord,
    transport: MemoryTransport,
    base: Url,
    object_url: Url,
}

#[allow(
    clippy::too_many_lines,
    reason = "Fixture builds a complete signed repository generation"
)]
fn fixture(status: &str, record_index_id: &str) -> Fixture {
    let key = SigningKey::from_bytes(&[17; 32]);
    let root_bytes = root(&key);
    let identity = IndexIdentity::new(
        IndexId::new("astrid").unwrap(),
        root_fingerprint_from_bytes(&root_bytes).unwrap(),
    );
    let record = record(record_index_id, "1.0.0");
    let object_bytes = serde_json::to_vec(&record).unwrap();
    let release_digest = record.publication_digest().to_string();
    let object_path = sparse_object_path(
        release_digest.split_once(':').unwrap().0,
        release_digest.split_once(':').unwrap().1,
    )
    .unwrap();
    let identity_string = format!("{}@{}", record.coordinate(), record.version());
    let shard = blake3::hash(identity_string.as_bytes()).as_bytes()[0];
    let entry = json!({
        "identity": identity_string,
        "namespace": record.coordinate().namespace.as_str(),
        "name": record.coordinate().name.as_str(),
        "version": record.version().to_string(),
        "release_digest": release_digest,
        "object": format!("v1/{object_path}"),
        "status": status,
        "authoritative": true,
        "artifact_locations": record.artifact().locations()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    });
    let base = Url::parse("memory://capsule-index/v1/").unwrap();
    let transport = MemoryTransport::new();
    let mut target_bytes = BTreeMap::<String, Vec<u8>>::new();
    for shard_number in 0..IDENTITY_SHARD_COUNT {
        let entries = if shard_number == usize::from(shard) {
            vec![entry.clone()]
        } else {
            Vec::new()
        };
        target_bytes.insert(
            format!("shards/{shard_number:02x}.json"),
            canonical(&json!({
                "schema": IDENTITY_SHARD_SCHEMA,
                "shard": format!("{shard_number:02x}"),
                "entries": entries
            })),
        );
    }
    target_bytes.insert(object_path.clone(), object_bytes);
    let mut target_meta = serde_json::Map::new();
    let mut object_url = None;
    for (path, bytes) in &target_bytes {
        let sha = hex::encode(sha2::Sha256::digest(bytes));
        target_meta.insert(
            path.clone(),
            json!({
                "length": bytes.len(),
                "hashes": { "sha256": sha }
            }),
        );
        let url = base.join(&format!("{sha}.{path}")).unwrap();
        transport.insert(&url, bytes.clone());
        if path == &object_path {
            object_url = Some(url);
        }
    }
    let targets = signed(
        &json!({
            "_type": "targets",
            "spec_version": "1.0.0",
            "version": 1,
            "expires": EXPIRES,
            "targets": target_meta
        }),
        &key,
    );
    let targets_sha = hex::encode(sha2::Sha256::digest(&targets));
    let snapshot = signed(
        &json!({
            "_type": "snapshot",
            "spec_version": "1.0.0",
            "version": 1,
            "expires": EXPIRES,
            "meta": {
                "targets.json": {
                    "version": 1,
                    "length": targets.len(),
                    "hashes": { "sha256": targets_sha }
                }
            }
        }),
        &key,
    );
    let snapshot_sha = hex::encode(sha2::Sha256::digest(&snapshot));
    let timestamp = signed(
        &json!({
            "_type": "timestamp",
            "spec_version": "1.0.0",
            "version": 1,
            "expires": EXPIRES,
            "meta": {
                "snapshot.json": {
                    "version": 1,
                    "length": snapshot.len(),
                    "hashes": { "sha256": snapshot_sha }
                }
            }
        }),
        &key,
    );
    transport
        .insert_path(&base, "timestamp.json", timestamp)
        .unwrap();
    transport
        .insert_path(&base, "1.snapshot.json", snapshot)
        .unwrap();
    transport
        .insert_path(&base, "1.targets.json", targets)
        .unwrap();
    Fixture {
        identity,
        record,
        transport,
        base,
        object_url: object_url.unwrap(),
    }
}

fn rotated_fixture(status: &str, record_index_id: &str, final_root_version: u64) -> Fixture {
    assert!(final_root_version >= 1);
    let fixture = fixture(status, record_index_id);
    let key = SigningKey::from_bytes(&[17; 32]);
    for version in 2..=final_root_version {
        fixture
            .transport
            .insert_path(
                &fixture.base,
                &format!("{version}.root.json"),
                root_version(&key, version),
            )
            .unwrap();
    }
    fixture
}

#[derive(Clone, Debug)]
struct DropObjectTransport {
    inner: MemoryTransport,
    blocked: Url,
}

#[tough::async_trait]
impl tough::Transport for DropObjectTransport {
    async fn fetch(&self, url: Url) -> Result<tough::TransportStream, tough::TransportError> {
        if url == self.blocked {
            return Err(tough::TransportError::new(
                tough::TransportErrorKind::FileNotFound,
                url,
            ));
        }
        self.inner.fetch(url).await
    }
}

fn client_config(fixture: &Fixture, dir: &Path) -> ClientConfig {
    let trust = TrustConfig::new(
        fixture.identity.clone(),
        root(&SigningKey::from_bytes(&[17; 32])),
        fixture.base.clone(),
        fixture.base.clone(),
        dir.join("state.json"),
        dir.join("datastore"),
    )
    .unwrap();
    ClientConfig::new(trust, dir.join("cache"))
}

#[test]
fn shard_parser_rejects_object_mismatch() {
    let fixture = fixture("active", "astrid");
    let shard = blake3::hash(
        format!(
            "{}@{}",
            fixture.record.coordinate(),
            fixture.record.version()
        )
        .as_bytes(),
    )
    .as_bytes()[0];
    let bytes = canonical(&json!({
        "schema": IDENTITY_SHARD_SCHEMA,
        "shard": format!("{shard:02x}"),
        "entries": [{
            "identity": format!("{}@{}", fixture.record.coordinate(), fixture.record.version()),
            "namespace": fixture.record.coordinate().namespace.as_str(),
            "name": fixture.record.coordinate().name.as_str(),
            "version": fixture.record.version().to_string(),
            "release_digest": fixture.record.publication_digest().to_string(),
            "object": "v1/objects/blake3/00/00.json",
            "status": "active",
            "authoritative": true,
            "artifact_locations": fixture.record.artifact().locations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        }]
    }));
    assert!(matches!(
        IdentityShard::parse(&bytes, 1024 * 1024),
        Err(Error::ObjectPathMismatch { .. })
    ));
}

#[tokio::test]
async fn resolves_one_source_and_proves_record_bindings() {
    let dir = tempdir().unwrap();
    let fixture = fixture("active", "astrid");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let resolved = client
        .resolve(
            fixture.transport.clone(),
            &coordinate,
            &VersionReq::parse("^1").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resolved.record.publication_digest(),
        fixture.record.publication_digest()
    );
    assert_eq!(
        resolved.artifact_locations,
        fixture.record.artifact().locations()
    );
    assert!(resolved.state.active_for_new_resolution());
}

#[tokio::test]
async fn wrong_index_record_is_rejected_without_fallback() {
    let dir = tempdir().unwrap();
    let fixture = fixture("active", "aos");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    assert!(matches!(
        client
            .resolve(
                fixture.transport,
                &coordinate,
                &VersionReq::parse("*").unwrap()
            )
            .await,
        Err(Error::RecordIdentityMismatch { .. })
    ));
}

#[tokio::test]
async fn missing_object_is_distinguished_from_shard_parse() {
    let dir = tempdir().unwrap();
    let fixture = fixture("active", "astrid");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let transport = DropObjectTransport {
        inner: fixture.transport,
        blocked: fixture.object_url,
    };
    let result = client
        .resolve(transport, &coordinate, &VersionReq::STAR)
        .await;
    assert!(matches!(result, Err(Error::MissingObject { .. })));
}

#[tokio::test]
async fn yanked_lock_remains_usable_but_revoked_lock_fails() {
    let dir = tempdir().unwrap();
    let yanked = fixture("yanked", "astrid");
    let client = IndexClient::new(client_config(&yanked, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let lock = LockRecord::from_publication(client.identity(), &yanked.record);
    let yanked_result = client
        .resolve(yanked.transport.clone(), &coordinate, &VersionReq::STAR)
        .await;
    assert!(matches!(
        yanked_result,
        Err(Error::Protocol(IndexError::NoMatchingPublication { .. }))
    ));
    let resolved = client
        .resolve_with_lock(yanked.transport, &coordinate, &VersionReq::STAR, &lock)
        .await
        .unwrap();
    assert!(resolved.state.is_yanked());

    let revoked_dir = tempdir().unwrap();
    let revoked = fixture("revoked", "astrid");
    let revoked_client = IndexClient::new(client_config(&revoked, revoked_dir.path()));
    let revoked_lock =
        LockRecord::from_publication(&revoked_client.identity().clone(), &revoked.record);
    assert!(matches!(
        revoked_client
            .resolve_with_lock(
                revoked.transport,
                &coordinate,
                &VersionReq::STAR,
                &revoked_lock,
            )
            .await,
        Err(Error::Protocol(IndexError::LockedPublicationRevoked(_)))
    ));
}

#[tokio::test]
async fn offline_exact_lock_requires_explicit_allow_expired_and_uses_atomic_cache() {
    let dir = tempdir().unwrap();
    let fixture = fixture("active", "astrid");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let resolved = client
        .resolve(fixture.transport.clone(), &coordinate, &VersionReq::STAR)
        .await
        .unwrap();
    let lock = LockRecord::from_publication(client.identity(), &resolved.record);
    assert!(matches!(
        client
            .resolve_locked_offline(&lock, OfflinePolicy::RejectExpired)
            .await,
        Err(Error::OfflineExpiryRequired)
    ));
    let offline = client
        .resolve_locked_offline(&lock, OfflinePolicy::AllowExpired)
        .await
        .unwrap();
    assert_eq!(
        offline.record.publication_digest(),
        resolved.record.publication_digest()
    );
}

#[tokio::test]
async fn offline_replays_bounded_multi_hop_root_rotation_witness() {
    let dir = tempdir().unwrap();
    let fixture = rotated_fixture("active", "astrid", 3);
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let resolved = client
        .resolve(fixture.transport, &coordinate, &VersionReq::STAR)
        .await
        .unwrap();
    let lock = LockRecord::from_publication(client.identity(), &resolved.record);
    let digest = lock.publication_digest();
    let hex = digest.hex();
    let chain_dir = dir
        .path()
        .join("cache")
        .join(digest.algorithm().as_str())
        .join(&hex[..2])
        .join(format!("{hex}.witness"))
        .join("root-chain");
    let root_two = tokio::fs::read(chain_dir.join("2.json")).await.unwrap();
    client
        .resolve_locked_offline(&lock, OfflinePolicy::AllowExpired)
        .await
        .unwrap();

    tokio::fs::remove_file(chain_dir.join("2.json"))
        .await
        .unwrap();
    assert!(matches!(
        client
            .resolve_locked_offline(&lock, OfflinePolicy::AllowExpired)
            .await,
        Err(Error::CacheCorrupt { .. })
    ));

    tokio::fs::write(chain_dir.join("2.json"), root_two)
        .await
        .unwrap();
    let root_three = tokio::fs::read(chain_dir.join("3.json")).await.unwrap();
    tokio::fs::write(chain_dir.join("2.json"), root_three)
        .await
        .unwrap();
    assert!(matches!(
        client
            .resolve_locked_offline(&lock, OfflinePolicy::AllowExpired)
            .await,
        Err(Error::Tuf(_) | Error::CacheCorrupt { .. })
    ));
}

#[tokio::test]
async fn offline_rejects_mutated_authenticated_shard_lifecycle() {
    let dir = tempdir().unwrap();
    let fixture = fixture("yanked", "astrid");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    let lock = LockRecord::from_publication(client.identity(), &fixture.record);
    client
        .resolve_with_lock(fixture.transport, &coordinate, &VersionReq::STAR, &lock)
        .await
        .unwrap();
    let digest = lock.publication_digest();
    let hex = digest.hex();
    let witness = dir
        .path()
        .join("cache")
        .join(digest.algorithm().as_str())
        .join(&hex[..2])
        .join(format!("{hex}.witness"));
    assert!(
        !dir.path()
            .join("cache")
            .join(digest.algorithm().as_str())
            .join(&hex[..2])
            .join(format!("{hex}.status.json"))
            .exists()
    );
    let shard_path = witness.join("shard.json");
    let mut shard = tokio::fs::read(&shard_path).await.unwrap();
    let yanked = b"yanked";
    let offset = shard
        .windows(yanked.len())
        .position(|window| window == yanked)
        .unwrap();
    shard[offset..offset + yanked.len()].copy_from_slice(b"active");
    tokio::fs::write(&shard_path, shard).await.unwrap();
    assert!(matches!(
        client
            .resolve_locked_offline(&lock, OfflinePolicy::AllowExpired)
            .await,
        Err(Error::Tuf(_) | Error::CacheCorrupt { .. })
    ));
}

#[tokio::test]
async fn stale_lock_does_not_fall_back_to_another_record() {
    let dir = tempdir().unwrap();
    let fixture = fixture("active", "astrid");
    let client = IndexClient::new(client_config(&fixture, dir.path()));
    let stale = record("astrid", "2.0.0");
    let lock = LockRecord::from_publication(client.identity(), &stale);
    let coordinate: Coordinate = "@official/demo-capsule".parse().unwrap();
    assert!(matches!(
        client
            .resolve_with_lock(fixture.transport, &coordinate, &VersionReq::STAR, &lock)
            .await,
        Err(Error::Protocol(IndexError::LockMismatch(_)))
    ));
}

#[test]
fn shard_parser_rejects_duplicate_mirror_locations() {
    let fixture = fixture("active", "astrid");
    let identity = format!(
        "{}@{}",
        fixture.record.coordinate(),
        fixture.record.version()
    );
    let shard = shard_for_identity(&identity);
    let location = fixture.record.artifact().locator().to_string();
    let bytes = canonical(&json!({
        "schema": IDENTITY_SHARD_SCHEMA,
        "shard": format!("{shard:02x}"),
        "entries": [{
            "identity": identity,
            "namespace": fixture.record.coordinate().namespace.as_str(),
            "name": fixture.record.coordinate().name.as_str(),
            "version": fixture.record.version().to_string(),
            "release_digest": fixture.record.publication_digest().to_string(),
            "object": format!("v1/{}", sparse_object_path_from_digest(fixture.record.publication_digest())),
            "status": "active",
            "authoritative": true,
            "artifact_locations": [location, location]
        }]
    }));
    assert!(matches!(
        IdentityShard::parse(&bytes, 1024 * 1024),
        Err(Error::ShardInvalid { .. })
    ));
}

#[test]
fn sealed_record_location_cannot_be_omitted_from_shard() {
    let fixture = fixture("active", "astrid");
    let entry = IdentityShardEntry {
        identity: format!(
            "{}@{}",
            fixture.record.coordinate(),
            fixture.record.version()
        ),
        coordinate: fixture.record.coordinate().clone(),
        version: fixture.record.version().clone(),
        release_digest: fixture.record.publication_digest().clone(),
        object: sparse_object_path_from_digest(fixture.record.publication_digest()),
        status: ShardStatus::Active,
        authoritative: true,
        artifact_locations: vec![MirrorUrl::new("https://mirror.example/capsule").unwrap()],
    };
    assert!(matches!(
        prove_record(&fixture.identity, &entry, &fixture.record),
        Err(Error::ArtifactLocationsMismatch { .. })
    ));
}
