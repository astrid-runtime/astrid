use super::runtime_tests::*;
use super::*;

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
