use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tar::Builder;

fn digest(prefix: &str, byte: u8) -> String {
    format!("{prefix}{}", hex::encode([byte; 32]))
}

fn sample_lock(manifest_digest: &str) -> StationLock {
    StationLock {
        schema: LOCK_SCHEMA_V2.to_owned(),
        station_id: "official".to_owned(),
        trust_root: digest("sha256:", 0x11),
        coordinate: astrid_core::kernel_api::StationCoordinate {
            namespace: "official".to_owned(),
            name: "demo".to_owned(),
        },
        version: "1.0.0".to_owned(),
        publication_digest: digest("blake3:", 0x22),
        artifact_size: 0,
        artifact_media_type: "application/vnd.astrid.capsule".to_owned(),
        artifact_sha256: digest("sha256:", 0x33),
        artifact_blake3: digest("blake3:", 0x44),
        manifest_digest: manifest_digest.to_owned(),
        capsule_content_digest: digest("blake3:", 0x55),
        package_digest: digest("blake3:", 0x66),
        component_count: 0,
        component_digest: digest("blake3:", 0x77),
        wit_digest: digest("blake3:", 0x88),
        capability_digest: digest("blake3:", 0x99),
        ipc_digest: digest("blake3:", 0xaa),
        runtime_abi_digest: digest("blake3:", 0xbb),
        dependency_digest: digest("blake3:", 0xcc),
        provenance_digest: digest("blake3:", 0xdd),
        source_digest: digest("blake3:", 0xee),
    }
}

fn capsule_archive(manifest: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.capsule");
    let file = File::create(&path).unwrap();
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "Capsule.toml", manifest)
        .unwrap();
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap();
    (dir, path)
}

#[cfg(unix)]
fn fake_station_script(dir: &Path, fixture: &Path, marker: &Path) -> PathBuf {
    let script = dir.join("astrid-station-fake");
    let body = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"{}\"\ncase \" $* \" in\n  *' source list '*) printf '%s\\n' '{{\"sources\":[{{\"id\":\"official\",\"enabled\":true}}]}}' ;;\n  *' fetch '*) prev=; out=; for arg in \"$@\"; do if [ \"$prev\" = '--output' ]; then out=\"$arg\"; cp \"{}\" \"$arg\"; fi; prev=\"$arg\"; done; printf '{{\"source\":\"official\",\"version\":\"1.0.0\",\"publication_digest\":\"{}\",\"output\":\"%s\"}}\\n' \"$out\" ;;\n  *) exit 97 ;;\nesac\n",
        marker.display(),
        fixture.display(),
        hex::encode([0x22_u8; 32]),
    );
    std::fs::write(&script, body).unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&script, permissions).unwrap();
    script
}

#[test]
fn manifest_digest_requires_canonical_station_form() {
    assert_eq!(
        decode_blake3("blake3:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .len(),
        32
    );
    assert!(
        decode_blake3("0000000000000000000000000000000000000000000000000000000000000000").is_err()
    );
    assert!(
        decode_blake3("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .is_err()
    );
}

#[test]
fn bare_station_commitments_are_normalized_before_fetch() {
    let manifest = "0".repeat(64);
    let mut lock = sample_lock(&manifest);
    lock.publication_digest = "1".repeat(64);
    lock.artifact_blake3 = "2".repeat(64);
    canonicalize_lock(&mut lock).unwrap();
    assert!(lock.publication_digest.starts_with("blake3:"));
    assert!(lock.artifact_blake3.starts_with("blake3:"));
    validate_lock(&lock).unwrap();
}

#[test]
fn station_stage_coordinate_is_strict() {
    assert!(validate_coordinate("@official/demo").is_ok());
    assert!(validate_coordinate("https://github.com/official/demo").is_err());
    assert!(validate_coordinate("@official/demo/extra").is_err());
}

#[test]
fn wrong_lock_schema_fails_closed() {
    let mut lock = sample_lock(&digest("blake3:", 0x01));
    lock.schema = "station-lock-v1".to_owned();
    assert!(validate_lock(&lock).is_err());
}

#[test]
fn manifest_digest_matches_exact_capsule_toml_bytes_and_normalizes_wire_form() {
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_dir, archive) = capsule_archive(manifest);
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(manifest);
    let digest = hasher.finalize().to_hex().to_string();
    let mut lock = sample_lock(&format!("blake3:{digest}"));
    verify_manifest_digest(&archive, &lock).unwrap();
    lock.manifest_digest = digest.clone();
    verify_manifest_digest(&archive, &lock).unwrap();
    lock.manifest_digest = format!("sha256:{digest}");
    assert!(verify_manifest_digest(&archive, &lock).is_err());
}

#[cfg(unix)]
#[test]
fn station_update_uses_existing_lock_and_private_handoff_not_astrid_cas() {
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    let astrid_home = root.path().join("astrid");
    std::fs::create_dir_all(&station_home).unwrap();
    std::fs::create_dir_all(&astrid_home).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(manifest);
    let mut lock = sample_lock(&format!("blake3:{}", hasher.finalize().to_hex()));
    // Older Station clients emitted bare BLAKE3 commitments. The update
    // path must normalize those before fetch and handoff side effects.
    lock.publication_digest = hex::encode([0x22_u8; 32]);
    lock.artifact_blake3 = hex::encode([0x44_u8; 32]);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker);

    assert!(is_configured_at(&script, &station_home).unwrap());
    let artifact = resolve_and_fetch_at("", None, Some(&lock), &script, &station_home).unwrap();

    let calls = std::fs::read_to_string(&marker).unwrap();
    assert!(calls.contains("fetch"));
    assert!(calls.contains("--lock"));
    assert!(!calls.contains(" resolve "));
    let expected_parent = station_home.join("var/sources/official/handoff");
    assert!(artifact.path.starts_with(expected_parent));
    assert!(!artifact.path.starts_with(astrid_home.join("var")));
    assert!(artifact.path.is_file());
    assert_eq!(artifact.lock.publication_digest, digest("blake3:", 0x22));
    assert_eq!(artifact.lock.artifact_blake3, digest("blake3:", 0x44));
}
