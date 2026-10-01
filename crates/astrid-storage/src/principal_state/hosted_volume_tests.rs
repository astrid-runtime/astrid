use super::runtime_tests::*;
use super::*;

#[tokio::test]
async fn compaction_reclaims_obsolete_representation_metadata_and_preserves_kv() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let mut store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    create_test_principal(&store, "alice").await;
    for cycle in 0_u64..3 {
        for value in 0_u64..128 {
            store
                .kv()
                .set(
                    "alice:capsule:shell",
                    "heartbeat",
                    (cycle * 128 + value).to_le_bytes().to_vec(),
                )
                .await
                .unwrap();
        }
        let before = std::fs::metadata(home.storage_volume_path()).unwrap().len();
        let policy = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            b"metadata-compaction-regression".to_vec(),
            Vec::new(),
            0,
            crate::storage_model::ObjectClass::Metadata,
        )
        .unwrap();
        store
            .compact_with_deterministic_proof(
                crate::storage_model::ObjectId::new([0xD1; 32]),
                policy,
                Vec::new(),
            )
            .await
            .unwrap();
        let after = std::fs::metadata(home.storage_volume_path()).unwrap().len();
        assert!(
            after < before / 2,
            "obsolete metadata retained: before={before}, after={after}"
        );
        store.engine.close().unwrap();
        drop(store);
        store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(
            store
                .kv()
                .get("alice:capsule:shell", "heartbeat")
                .await
                .unwrap(),
            Some((cycle * 128 + 127).to_le_bytes().to_vec())
        );
    }
    store.engine.close().unwrap();
}

#[tokio::test]
#[ignore = "sustained real principal KV diagnostic; run explicitly"]
async fn repeated_compaction_cycles_account_for_retained_growth() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let mut store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    create_test_principal(&store, "alice").await;
    for cycle in 0_u64..10 {
        let started = std::time::Instant::now();
        for value in 0_u64..256 {
            store
                .kv()
                .set(
                    "alice:capsule:shell",
                    "heartbeat",
                    (cycle * 256 + value).to_le_bytes().to_vec(),
                )
                .await
                .unwrap();
        }
        let write_ms = started.elapsed().as_millis();
        let before = std::fs::metadata(home.storage_volume_path()).unwrap().len();
        assert!(
            before < 256 * 1024 * 1024,
            "fixture exceeded safety ceiling"
        );
        let policy = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            b"cycle-probe-retention".to_vec(),
            Vec::new(),
            0,
            crate::storage_model::ObjectClass::Metadata,
        )
        .unwrap();
        let compact_started = std::time::Instant::now();
        store
            .compact_with_deterministic_proof(
                crate::storage_model::ObjectId::new([0xD2; 32]),
                policy,
                Vec::new(),
            )
            .await
            .unwrap();
        let compact_ms = compact_started.elapsed().as_millis();
        // Do not acknowledge evidence without an independent durable sink merely
        // to improve the measured footprint. Account for the retained outbox.
        let pending = store.pending_compaction_evidence().unwrap().len();
        let after = std::fs::metadata(home.storage_volume_path()).unwrap().len();
        eprintln!(
            "cycle={cycle} write_ms={write_ms} compact_ms={compact_ms} before={before} after={after} pending_receipts={pending}"
        );
        store.engine.close().unwrap();
        drop(store);
        report_retained_regions(&home.storage_volume_path());
        store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(
            store
                .kv()
                .get("alice:capsule:shell", "heartbeat")
                .await
                .unwrap(),
            Some((cycle * 256 + 255).to_le_bytes().to_vec())
        );
    }
    store.engine.close().unwrap();
}

#[tokio::test]
#[ignore = "sustained real principal KV diagnostic; run explicitly"]
async fn repeated_principal_kv_writes_measure_volume_growth_and_recover() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let mut store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    create_test_principal(&store, "alice").await;
    let path = home.storage_volume_path();
    let baseline = std::fs::metadata(&path).unwrap().len();
    let started = std::time::Instant::now();
    for batch in 1_u64..=8 {
        for index in 0_u64..250 {
            let value = (batch * 250 + index).to_le_bytes().to_vec();
            store
                .kv()
                .set("alice:capsule:shell", "heartbeat", value)
                .await
                .unwrap();
        }
        let expected = (batch * 250 + 249).to_le_bytes().to_vec();
        store.engine.close().unwrap();
        drop(store);
        let metadata = std::fs::metadata(&path).unwrap();
        // Fixture safety ceiling, not a claim about acceptable amplification.
        assert!(metadata.len() < 256 * 1024 * 1024, "probe exceeded 256 MiB");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            eprintln!(
                "principal_kv_writes={} elapsed_ms={} file_bytes={} allocated_bytes={} growth={}",
                batch * 250,
                started.elapsed().as_millis(),
                metadata.len(),
                metadata.blocks() * 512,
                metadata.len() - baseline
            );
        }
        store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(
            store
                .kv()
                .get("alice:capsule:shell", "heartbeat")
                .await
                .unwrap(),
            Some(expected)
        );
    }
    let before_noop = std::fs::metadata(&path).unwrap().len();
    repeat_unchanged_heartbeat(&store).await;
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        before_noop,
        "unchanged KV writes grew volume"
    );
    let policy = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"growth-probe-retention".to_vec(),
        Vec::new(),
        0,
        crate::storage_model::ObjectClass::Metadata,
    )
    .unwrap();
    let report = store
        .compact_with_deterministic_proof(
            crate::storage_model::ObjectId::new([0xD0; 32]),
            policy,
            Vec::new(),
        )
        .await
        .unwrap();
    let after_compaction = std::fs::metadata(&path).unwrap().len();
    assert!(
        after_compaction < before_noop / 2,
        "obsolete representation history survived compaction"
    );
    eprintln!(
        "principal_kv_compaction before={before_noop} after={after_compaction} objects_reclaimed={} arena_before={} arena_after={}",
        report.objects_reclaimed(),
        report.arena_bytes_before(),
        report.arena_bytes_after()
    );
    store.engine.close().unwrap();
    drop(store);
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get("alice:capsule:shell", "heartbeat")
            .await
            .unwrap(),
        Some(2249_u64.to_le_bytes().to_vec())
    );
    reopened.engine.close().unwrap();
    drop(reopened);
    report_retained_regions(&path);
}

async fn repeat_unchanged_heartbeat(store: &RuntimePrincipalStore) {
    for _ in 0..1000 {
        store
            .kv()
            .set(
                "alice:capsule:shell",
                "heartbeat",
                2249_u64.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
}

fn report_retained_regions(path: &std::path::Path) {
    use crate::volume::{AstridVolume, HostedFileVolume};
    let volume = HostedFileVolume::open(path).unwrap();
    for region in volume.list_regions("").unwrap() {
        eprintln!(
            "retained_region={} logical_bytes={}",
            region.as_str(),
            volume.region_len(&region).unwrap()
        );
    }
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn hosted_volume_retires_a_torn_tail_and_reopens_committed_roots() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_test_principal(&store, "alice").await;
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    store
        .kv()
        .set("alice:capsule:shell", "theme", b"raven".to_vec())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);

    let path = home.storage_volume_path();
    let committed_len = std::fs::metadata(&path).unwrap().len();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&[0xA5; 17]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    assert_eq!(
        reopened
            .engine
            .root(&StateOwner::Principal(alice_uid))
            .unwrap()
            .unwrap()
            .generation,
        RootGeneration::new(1)
    );
    assert_eq!(
        reopened
            .kv()
            .get("alice:capsule:shell", "theme")
            .await
            .unwrap(),
        Some(b"raven".to_vec())
    );
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn hosted_volume_rejects_interior_container_corruption_on_header_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);

    let path = home.storage_volume_path();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[8] ^= 0x80;
    std::fs::write(&path, bytes).unwrap();

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .expect("valid footer should bypass interior journal scanning");
    reopened.engine.close().unwrap();
    drop(reopened);

    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 0x80;
    std::fs::write(&path, bytes).unwrap();

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("corrupt Astrid volume unexpectedly reopened");
    };
    assert!(error.to_string().contains("record magic"), "{error}");
}

#[tokio::test]
async fn independent_reader_accepts_a_rust_produced_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_test_principal(&store, "alice").await;
    let alice = alice_uid.to_string();
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    let owner = StateOwner::Principal(alice_uid);
    let name = ContentName::new("workspace/fastcdc-golden.bin").unwrap();
    store
        .content()
        .put(&owner, &name, &chunker_golden_source(1024 * 1024))
        .unwrap();
    drop(store);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(home.storage_volume_path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decoded["roots"][alice.as_str()]["generation"], 1);
    assert_eq!(decoded["roots"][alice.as_str()]["kv"]["entries"], 1);
    assert_eq!(
        decoded["roots"][alice.as_str()]["kv"]["logical_bytes"],
        b"/workspace".len()
    );
    assert!(
        decoded["roots"][alice.as_str()]["commit"]
            .as_str()
            .unwrap()
            .starts_with("1:1:32:")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Evidence")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Commit")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "File")
    );
    assert_eq!(
        decoded["content_catalog_spec_object"],
        format!(
            "1:1:32:{}",
            object_id_hex(
                Blake3ObjectIdentityV1
                    .identify(&bootstrap::content_catalog_format_specification().unwrap(),)
            )
        )
    );

    let volume_path = home.storage_volume_path();
    let mut volume = std::fs::read(&volume_path).unwrap();
    volume[43] ^= 0x80;
    std::fs::write(&volume_path, volume).unwrap();
    let rejected = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py"))
        .arg(volume_path)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "independent reader accepted a corrupt Rust-produced volume"
    );
}

#[test]
fn independent_volume_validator_rejects_the_full_unicode_control_set() {
    let script_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let output = std::process::Command::new("python3")
        .current_dir(script_directory)
        .arg("-c")
        .arg(
            r#"from runatal_v1_volume import VolumeFormatError, volume_region_name
for codepoint in range(0x80, 0xa0):
    try:
        volume_region_name(chr(codepoint).encode())
    except VolumeFormatError:
        continue
    raise AssertionError(f"U+{codepoint:04X} was accepted")
assert volume_region_name(" Astrid ".encode()) == " Astrid ""#,
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent validator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
