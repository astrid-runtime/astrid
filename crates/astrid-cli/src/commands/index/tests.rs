use std::sync::{Arc, Barrier};
use std::thread;

use super::*;

fn store() -> (tempfile::TempDir, IndexStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = IndexStore::new(dir.path().join("etc").join("indexes.toml"));
    (dir, store)
}

fn root_args(id: &str, bytes: &[u8], url: &str) -> AddArgs {
    AddArgs {
        id: id.to_owned(),
        base_url: url.to_owned(),
        root: RootInput::Bytes(bytes.to_vec()),
        fingerprint: root_fingerprint(bytes),
        enabled: true,
        priority: 10,
    }
}

fn builtin_source(bytes: &[u8]) -> BuiltinSource {
    BuiltinSource::new(IndexSource {
        id: BUILTIN_INDEX_ID.to_owned(),
        base_url: "https://index.astrid.example/".to_owned(),
        root: PinnedRoot::from_bytes(bytes, &root_fingerprint(bytes)).expect("root"),
        enabled: true,
        priority: 0,
        built_in: true,
        metadata: None,
    })
    .expect("builtin")
}

#[test]
fn add_persists_stable_sorted_config_and_loads() {
    let (_dir, store) = store();
    store
        .add(root_args("zeta", b"zeta", "https://zeta.example"))
        .expect("add zeta");
    store
        .add(root_args("alpha", b"alpha", "https://alpha.example"))
        .expect("add alpha");

    let text = std::fs::read_to_string(&store.paths().config).expect("config");
    assert!(
        text.find("id = \"alpha\"").expect("alpha") < text.find("id = \"zeta\"").expect("zeta")
    );
    assert_eq!(store.load().expect("load")[0].id, "alpha");
    assert_eq!(
        store
            .list(ListArgs {
                format: IndexListFormat::Json
            })
            .expect("json")
            .matches("\"id\"")
            .count(),
        2
    );
}

#[test]
fn corrupt_config_is_an_error_and_stale_interrupted_temp_is_ignored() {
    let (dir, corrupt_store) = store();
    std::fs::create_dir_all(corrupt_store.paths().config.parent().expect("parent")).expect("mkdir");
    std::fs::write(&corrupt_store.paths().config, "schema-version = [").expect("corrupt");
    assert!(matches!(
        corrupt_store.load(),
        Err(IndexError::CorruptConfig { .. })
    ));

    let (_dir2, good_store) = store();
    good_store
        .add(root_args("good", b"good", "https://good.example"))
        .expect("add");
    let stale = good_store
        .paths()
        .config
        .parent()
        .expect("parent")
        .join(".indexes.interrupted.tmp");
    std::fs::write(&stale, "this write was interrupted").expect("stale");
    assert_eq!(good_store.load().expect("load")[0].id, "good");
    assert!(stale.exists());
    assert!(dir.path().exists());
}

#[test]
fn duplicate_ids_roots_and_urls_are_rejected() {
    let (_dir, store) = store();
    store
        .add(root_args("one", b"one", "https://one.example"))
        .expect("add");
    assert!(matches!(
        store.add(root_args("one", b"two", "https://two.example")),
        Err(IndexError::DuplicateId(_))
    ));
    assert!(matches!(
        store.add(root_args("two", b"one", "https://two.example")),
        Err(IndexError::DuplicateTrustRoot { .. })
    ));
    assert!(matches!(
        store.add(root_args("three", b"three", "https://one.example")),
        Err(IndexError::DuplicateUrl { .. })
    ));
}

#[test]
fn url_and_name_attacks_are_rejected_but_loopback_http_is_allowed() {
    for url in [
        "http://not-loopback.example",
        "https://user:pass@example",
        "https://example/path?query=1",
        "https://example/path#fragment",
        "https://example/a/../b",
        "https://example/a/%2e%2e/b",
        "https://example/a/%252e%252e/b",
    ] {
        assert!(validate_base_url(url).is_err(), "must reject {url}");
    }
    assert!(validate_base_url("http://127.0.0.1:8000/index/").is_ok());
    assert!(validate_base_url("http://[::1]:8000/index/").is_ok());
    assert_eq!(
        validate_base_url("https://example:443/index").expect("canonical URL"),
        "https://example/index/"
    );
    assert!(validate_index_id("../evil").is_err());
    assert!(validate_index_id("MixedCase").is_err());
    assert!(validate_root_path(std::path::Path::new("../root.json")).is_err());
}

#[test]
fn trust_root_identity_uses_tagged_sha256_and_rejects_bare_persistence() {
    let bytes = b"root-bytes";
    let root = PinnedRoot::from_bytes(bytes, &root_fingerprint(bytes)).expect("root");
    assert!(root.fingerprint.starts_with("sha256:"));
    let source = IndexSource {
        id: "third-party".to_owned(),
        base_url: "https://index.example/".to_owned(),
        root: root.clone(),
        enabled: true,
        priority: 1,
        built_in: false,
        metadata: None,
    };
    assert_eq!(
        root.fingerprint,
        source
            .protocol_identity()
            .expect("protocol identity")
            .trust_root
            .to_string(),
        "the stored spelling must be the protocol spelling"
    );
    let mut bare = root;
    bare.fingerprint = bare
        .fingerprint
        .strip_prefix("sha256:")
        .expect("tag")
        .to_owned();
    assert!(matches!(
        bare.validate(),
        Err(IndexError::InvalidFingerprint(_))
    ));
}

#[test]
fn uncompiled_builtin_record_is_not_accepted_as_a_third_party_source() {
    let (_dir, store) = store();
    assert!(matches!(
        store.remove(
            RemoveArgs {
                id: BUILTIN_INDEX_ID.to_owned()
            },
            &NoUsage,
        ),
        Err(IndexError::BuiltinProtected)
    ));
    let mut source = builtin_source(b"builtin-root").source;
    source.built_in = false;
    let config = IndexConfig {
        schema_version: CONFIG_SCHEMA_VERSION,
        sources: vec![source],
    };
    std::fs::create_dir_all(store.paths().config.parent().expect("parent")).expect("mkdir");
    std::fs::write(
        &store.paths().config,
        toml::to_string(&config).expect("toml"),
    )
    .expect("write");
    assert!(matches!(
        store.load(),
        Err(IndexError::BuiltinRootUnavailable)
    ));
}

#[test]
fn builtin_cannot_be_added_removed_or_repointed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let builtin = builtin_source(b"builtin-root");
    let store = IndexStore::from_home(dir.path(), Some(builtin.clone()));
    assert!(matches!(
        store.add(root_args(BUILTIN_INDEX_ID, b"user", "https://user.example")),
        Err(IndexError::BuiltinProtected)
    ));
    let source = store.load().expect("load")[0].clone();
    assert!(source.built_in);
    let blocked = store.remove(
        RemoveArgs {
            id: BUILTIN_INDEX_ID.to_owned(),
        },
        &NoUsage,
    );
    assert!(matches!(blocked, Err(IndexError::BuiltinProtected)));

    std::fs::create_dir_all(store.paths().config.parent().expect("parent")).expect("mkdir");
    let mut tampered = IndexConfig {
        schema_version: CONFIG_SCHEMA_VERSION,
        sources: vec![IndexSource {
            base_url: "https://attacker.example/".to_owned(),
            ..source
        }],
    };
    tampered.sources[0].built_in = true;
    std::fs::write(
        &store.paths().config,
        tampered.to_stable_toml().expect("toml"),
    )
    .expect("write");
    assert!(matches!(store.load(), Err(IndexError::BuiltinRepointed)));
}

struct StaticTransport {
    response: RefreshResponse,
}

impl RefreshTransport for StaticTransport {
    fn refresh(&self, _source: &IndexSource) -> Result<RefreshResponse, IndexError> {
        Ok(self.response.clone())
    }
}

struct TestVerifier;

impl MetadataVerifier for TestVerifier {
    fn verify(
        &self,
        _source: &IndexSource,
        _root: &[u8],
        metadata: &[u8],
        _previous: Option<&MetadataSnapshot>,
    ) -> Result<VerifiedMetadata, IndexError> {
        Ok(VerifiedMetadata {
            version: 1,
            bytes: metadata.to_vec(),
            digest: metadata_digest(metadata),
        })
    }
}

#[test]
fn update_rejects_root_replacement_and_persists_verified_metadata() {
    let (_dir, store) = store();
    store
        .add(root_args("one", b"one-root", "https://one.example"))
        .expect("add");
    let changed = StaticTransport {
        response: RefreshResponse {
            root: Some(b"new-root".to_vec()),
            metadata: b"metadata".to_vec(),
        },
    };
    assert!(matches!(
        store.update(
            UpdateArgs {
                id: "one".to_owned()
            },
            &changed,
            &TestVerifier
        ),
        Err(IndexError::RootMismatch { .. })
    ));
    let valid = StaticTransport {
        response: RefreshResponse {
            root: Some(b"one-root".to_vec()),
            metadata: b"metadata".to_vec(),
        },
    };
    let outcome = store
        .update(
            UpdateArgs {
                id: "one".to_owned(),
            },
            &valid,
            &TestVerifier,
        )
        .expect("update");
    assert_eq!(outcome.snapshot.version, 1);
    assert!(store.load().expect("load")[0].metadata.is_some());
}

#[test]
fn remove_returns_structured_blocked_result_when_in_use() {
    let (_dir, store) = store();
    store
        .add(root_args("one", b"one", "https://one.example"))
        .expect("add");
    let outcome = store
        .remove(
            RemoveArgs {
                id: "one".to_owned(),
            },
            &InUse,
        )
        .expect("remove");
    assert_eq!(
        outcome,
        RemoveOutcome::Blocked {
            id: "one".to_owned(),
            references: vec!["workspace.lock".to_owned(), "aos.lock".to_owned()]
        }
    );
    assert_eq!(store.load().expect("load").len(), 1);
}

#[test]
fn concurrent_updates_serialize_without_losing_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(IndexStore::new(dir.path().join("etc").join("indexes.toml")));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for number in 0..4 {
        let worker = Arc::clone(&store);
        let start = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            start.wait();
            worker
                .add(root_args(
                    &format!("source{number}"),
                    format!("root{number}").as_bytes(),
                    &format!("https://source{number}.example"),
                ))
                .expect("serialized add");
        }));
    }
    for handle in handles {
        handle.join().expect("join");
    }
    assert_eq!(store.load().expect("load").len(), 4);
}

#[test]
fn concurrent_metadata_updates_serialize_without_losing_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(IndexStore::new(dir.path().join("etc").join("indexes.toml")));
    store
        .add(root_args("one", b"one-root", "https://one.example"))
        .expect("add");
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let worker = Arc::clone(&store);
        let start = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            start.wait();
            worker
                .update(
                    UpdateArgs {
                        id: "one".to_owned(),
                    },
                    &StaticTransport {
                        response: RefreshResponse {
                            root: Some(b"one-root".to_vec()),
                            metadata: b"metadata".to_vec(),
                        },
                    },
                    &TestVerifier,
                )
                .expect("serialized update");
        }));
    }
    for handle in handles {
        handle.join().expect("join");
    }
    let sources = store.load().expect("load");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].id, "one");
    assert_eq!(
        sources[0]
            .metadata
            .as_ref()
            .map(|snapshot| snapshot.version),
        Some(1)
    );
}

#[test]
fn explicit_rotation_requires_verifier_path() {
    let (_dir, store) = store();
    store
        .add(root_args("one", b"one", "https://one.example"))
        .expect("add");
    let result = store.rotate_root(
        RootRotation {
            id: "one".to_owned(),
            root: RootInput::Bytes(b"new".to_vec()),
            fingerprint: root_fingerprint(b"new"),
            proof: b"proof".to_vec(),
        },
        &TestVerifier,
    );
    assert!(matches!(
        result,
        Err(IndexError::RootRotationRefused { .. })
    ));
}

#[test]
fn lock_usage_scanner_blocks_json_toml_and_skips_binary_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let json_path = dir.path().join("astrid.lock");
    std::fs::write(
        &json_path,
        r#"{"index_id":"one","coordinate":"@demo/capsule"}"#,
    )
    .expect("json");
    let toml_path = dir.path().join("other.lock");
    std::fs::write(&toml_path, "index-id = \"two\"\n").expect("toml");
    let binary_path = dir.path().join("binary.lock");
    std::fs::write(&binary_path, [0, 159, 146, 0]).expect("binary");

    let scanner = LockUsageScanner::new(vec![dir.path().to_owned()]);
    let references = scanner.references("one").expect("scan");
    assert_eq!(references, vec![json_path.to_string_lossy().into_owned()]);
    assert!(
        scanner
            .references("two")
            .expect("scan")
            .contains(&toml_path.to_string_lossy().into_owned())
    );
    assert!(
        LockUsageScanner::new(vec![dir.path().join("does-not-exist")])
            .references("one")
            .expect("missing roots are skipped")
            .is_empty()
    );
}

#[test]
fn lock_usage_scanner_has_explicit_depth_and_file_caps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nested = dir.path().join("a").join("b");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::write(nested.join("astrid.lock"), "index_id = \"one\"").expect("lock");
    assert!(matches!(
        LockUsageScanner::new(vec![dir.path().to_owned()])
            .max_depth(1)
            .references("one"),
        Err(IndexError::Usage(_))
    ));
    assert!(matches!(
        LockUsageScanner::new(vec![dir.path().to_owned()])
            .max_files(1)
            .references("one"),
        Ok(_)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn reqwest_transport_rejects_credentials_before_network() {
    let transport = ReqwestTufTransport::new(1024).expect("client");
    let result = tough::Transport::fetch(
        &transport,
        url::Url::parse("https://user:pass@example.invalid/root.json").expect("url"),
    )
    .await;
    assert!(result.is_err());
}

struct NoUsage;

impl UsageChecker for NoUsage {
    fn references(&self, _id: &str) -> Result<Vec<String>, IndexError> {
        Ok(Vec::new())
    }
}

struct InUse;

impl UsageChecker for InUse {
    fn references(&self, _id: &str) -> Result<Vec<String>, IndexError> {
        Ok(vec!["workspace.lock".to_owned(), "aos.lock".to_owned()])
    }
}
