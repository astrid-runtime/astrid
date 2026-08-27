//! Integration regressions for Station lock lifetime and bare-hex persistence.
//! Kept beside [`super`] so `station.rs` stays under the file cap.

use super::*;
use crate::commands::capsule::install::ManualInstallOptions;
use crate::commands::capsule::install::test_daemon_install_call;
use crate::commands::capsule::install_update::{DaemonUpdateSource, daemon_update_source};
use crate::commands::capsule::remove::test_remove_capsule_from_home_for_in_workspace;
use crate::commands::capsule::show::CapsuleShow;
use crate::commands::capsule::show::registry_identity;
use astrid_core::kernel_api::CapsuleMetadataEntry;
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::Digest as _;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tar::Builder;

static PROCESS_SETTINGS_LOCK: Mutex<()> = Mutex::new(());

mod station_rollback_tests;

struct CurrentDirGuard {
    _lock: MutexGuard<'static, ()>,
    old_current_dir: PathBuf,
}

impl CurrentDirGuard {
    fn install(cwd: &Path) -> Self {
        let lock = PROCESS_SETTINGS_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let guard = Self {
            _lock: lock,
            old_current_dir: std::env::current_dir().unwrap(),
        };
        std::env::set_current_dir(cwd).unwrap();
        guard
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.old_current_dir);
    }
}

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

fn fake_station_script(dir: &Path, fixture: &Path, marker: &Path, lock_json: &Path) -> PathBuf {
    let script = dir.join("astrid-station-fake");
    let body = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{marker}"
case " $* " in
  *' source list '*) printf '%s\n' '{{"sources":[{{"id":"official","enabled":true}}]}}' ;;
  *' resolve '*)
    prev=
    for arg in "$@"; do
      if [ "$prev" = '--write-lock' ]; then
        cp "{lock}" "$arg"
      fi
      prev="$arg"
    done
    printf '{{"lock":'
    cat "{lock}"
    printf '}}\n'
    ;;
  *' fetch '*)
    prev=
    out=
    for arg in "$@"; do
      if [ "$prev" = '--output' ]; then
        out="$arg"
        cp "{fixture}" "$arg"
      fi
      prev="$arg"
    done
    printf '{{"source":"official","version":"1.0.0","publication_digest":"{publication}","output":"%s"}}\n' "$out"
    ;;
  *) exit 97 ;;
esac
"#,
        marker = marker.display(),
        lock = lock_json.display(),
        fixture = fixture.display(),
        publication = hex::encode([0x22_u8; 32]),
    );
    std::fs::write(&script, body).unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&script, permissions).unwrap();
    script
}

fn metadata_without_update_source() -> CapsuleMetadataEntry {
    CapsuleMetadataEntry {
        name: "demo".to_owned(),
        version: "1.0.0".to_owned(),
        description: None,
        interceptor_events: Vec::new(),
        imports: std::collections::HashMap::new(),
        exports: std::collections::HashMap::new(),
        capabilities: serde_json::Value::Null,
        env: std::collections::HashMap::new(),
        wit_hashes: Vec::new(),
        wasm_hash: None,
        update_source: None,
        source_id: None,
        owner_uid: None,
        registry_source: None,
    }
}

fn registry_source(lock: Option<&StationLock>) -> Option<String> {
    lock.map(|lock| {
        format!(
            "@{}/{} ({})",
            lock.coordinate.namespace, lock.coordinate.name, lock.publication_digest
        )
    })
}

fn show_record(lock: Option<&StationLock>) -> CapsuleShow {
    CapsuleShow {
        name: "demo".into(),
        version: "1.0.0".into(),
        source: "8d5f2f7d-c89f-4d8f-9ac8-4b5e3d7c7b2d".into(),
        wasm_hash: String::new(),
        installed_at: String::new(),
        updated_at: String::new(),
        contracts_pin: None,
        contracts_canonical: None,
        contracts_status: "daemon-registry".into(),
        manifest: String::new(),
        permissions: Vec::new(),
        registry_source: registry_source(lock),
    }
}

fn write_lock_json(path: &Path, lock: &StationLock) {
    std::fs::write(path, serde_json::to_vec_pretty(lock).unwrap()).unwrap();
}

fn lock_file_sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)))
}

fn domain_digest(manifest: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(manifest);
    hasher.finalize().to_hex().to_string()
}

fn lock_for_archive(archive: &Path, manifest: &[u8]) -> StationLock {
    let bytes = std::fs::read(archive).unwrap();
    let mut lock = sample_lock(&format!("blake3:{}", domain_digest(manifest)));
    lock.artifact_size = bytes.len() as u64;
    lock.artifact_sha256 = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)));
    lock.artifact_blake3 = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    lock
}

#[test]
fn station_handoff_rejects_artifact_byte_substitution_before_lock_persist() {
    let root = tempfile::tempdir().unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let lock = lock_for_archive(&archive, manifest);
    let lock_path = root.path().join("handoff.lock.json");
    write_lock_json(&lock_path, &lock);
    let lock_sha256 = lock_file_sha256(&lock_path);
    let original = std::fs::read(&archive).unwrap();
    let mut substituted = original.clone();
    substituted[0] ^= 0xff;
    std::fs::write(&archive, substituted).unwrap();

    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _lock_backend = runtime.block_on(super::test_lock_backend::install());
    let result = runtime.block_on(
        crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
            &crate::commands::capsule::install::StationInstallRequest {
                source: archive.to_str().unwrap(),
                capsule: None,
                workspace: false,
                yes: true,
                approve_untrusted: true,
                station_lock: Some(lock_path.as_path()),
                station_lock_sha256: Some(lock_sha256.as_str()),
                vars: &[],
            },
            &home,
        ),
    );
    assert!(
        result.is_err(),
        "substituted archive was handed to the daemon"
    );
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_none(),
        "artifact substitution must fail before Station lock persistence"
    );
}

#[test]
fn station_handoff_rejects_lock_byte_substitution_before_lock_persist() {
    let root = tempfile::tempdir().unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let mut lock = lock_for_archive(&archive, manifest);
    let lock_path = root.path().join("handoff.lock.json");
    write_lock_json(&lock_path, &lock);
    let lock_sha256 = lock_file_sha256(&lock_path);
    lock.station_id = "attacker-controlled-source".to_owned();
    write_lock_json(&lock_path, &lock);

    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _lock_backend = runtime.block_on(super::test_lock_backend::install());
    let result = runtime.block_on(
        crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
            &crate::commands::capsule::install::StationInstallRequest {
                source: archive.to_str().unwrap(),
                capsule: None,
                workspace: false,
                yes: true,
                approve_untrusted: true,
                station_lock: Some(lock_path.as_path()),
                station_lock_sha256: Some(lock_sha256.as_str()),
                vars: &[],
            },
            &home,
        ),
    );
    assert!(result.is_err(), "substituted lock was handed to the daemon");
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_none(),
        "lock substitution must fail before Station lock persistence"
    );
}

#[tokio::test]
async fn station_private_handoff_persists_lock_show_and_update_source() {
    let root = tempfile::tempdir().unwrap();
    let workspace_root = root.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let _current_dir = CurrentDirGuard::install(&workspace_root);
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let expected = lock_for_archive(&archive, manifest);
    let lock_path = root.path().join("handoff.lock.json");
    write_lock_json(&lock_path, &expected);
    let lock_sha256 = lock_file_sha256(&lock_path);

    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _lock_backend = super::test_lock_backend::install().await;
    let mut previous = sample_lock(&digest("blake3:", 0x01));
    previous.station_id = "previous-registry".to_owned();
    store_lock(&principal, "demo", previous.clone())
        .await
        .unwrap();
    let _local_backend = crate::commands::capsule::install::test_local_install_backend(false);
    crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
        &crate::commands::capsule::install::StationInstallRequest {
            source: archive.to_str().unwrap(),
            capsule: None,
            workspace: false,
            yes: true,
            approve_untrusted: true,
            station_lock: Some(lock_path.as_path()),
            station_lock_sha256: Some(lock_sha256.as_str()),
            vars: &[],
        },
        &home,
    )
    .await
    .unwrap();
    assert_eq!(
        super::test_lock_backend::set_calls(),
        2,
        "handoff must replace seeded provenance without extra writes"
    );

    let persisted = load_lock(&principal, "demo")
        .await
        .unwrap()
        .expect("StationLockGet must observe the owner-scoped handoff");
    assert_eq!(persisted, expected);
    assert_ne!(persisted.station_id, previous.station_id);

    let (daemon_source, daemon_calls) = test_daemon_install_call()
        .expect("private staging must reach the daemon local-install boundary");
    assert_eq!(daemon_calls, 1);
    {
        let source_path = std::path::Path::new(daemon_source.as_str());
        assert!(
            source_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with("astrid-station-handoff-")),
            "daemon must receive a create-new staged archive: {:?}",
            source_path.display()
        );
    }
    assert_eq!(
        registry_identity(Some(&persisted)).as_deref(),
        Some(
            format!(
                "@{}/{} ({})",
                persisted.coordinate.namespace,
                persisted.coordinate.name,
                persisted.publication_digest
            )
            .as_str()
        )
    );

    let entry = metadata_without_update_source();
    assert!(matches!(
        daemon_update_source(&entry, Some(persisted)),
        DaemonUpdateSource::Station(_)
    ));
}

#[tokio::test]
async fn station_handoff_failure_restores_previous_owner_scoped_lock() {
    let root = tempfile::tempdir().unwrap();
    let workspace_root = root.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let _current_dir = CurrentDirGuard::install(&workspace_root);
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let lock = lock_for_archive(&archive, manifest);
    let lock_path = root.path().join("handoff.lock.json");
    write_lock_json(&lock_path, &lock);
    let lock_sha256 = lock_file_sha256(&lock_path);

    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _lock_backend = super::test_lock_backend::install().await;
    let previous = sample_lock(&digest("blake3:", 0x01));
    store_lock(&principal, "demo", previous.clone())
        .await
        .unwrap();
    let _local_backend = crate::commands::capsule::install::test_local_install_backend(true);
    let error =
        crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
            &crate::commands::capsule::install::StationInstallRequest {
                source: archive.to_str().unwrap(),
                capsule: None,
                workspace: false,
                yes: true,
                approve_untrusted: true,
                station_lock: Some(lock_path.as_path()),
                station_lock_sha256: Some(lock_sha256.as_str()),
                vars: &[],
            },
            &home,
        )
        .await
        .expect_err("failure after persistence must fail the command");
    assert!(error.to_string().contains("daemon install failed"));
    assert_eq!(
        load_lock(&principal, "demo").await.unwrap().as_ref(),
        Some(&previous)
    );
    assert_eq!(
        super::test_lock_backend::set_calls(),
        3,
        "failed handoff must write replacement then restore the previous lock"
    );
}

#[tokio::test]
async fn ordinary_local_install_without_station_flags_performs_no_lock_set() {
    let root = tempfile::tempdir().unwrap();
    let workspace_root = root.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let _current_dir = CurrentDirGuard::install(&workspace_root);
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _lock_backend = super::test_lock_backend::install().await;
    let _local_backend = crate::commands::capsule::install::test_local_install_backend(false);

    crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
        &crate::commands::capsule::install::StationInstallRequest {
            source: archive.to_str().unwrap(),
            capsule: None,
            workspace: false,
            yes: true,
            approve_untrusted: false,
            station_lock: None,
            station_lock_sha256: None,
            vars: &[],
        },
        &home,
    )
    .await
    .unwrap();

    assert_eq!(super::test_lock_backend::set_calls(), 0);
    let (daemon_source, calls) = test_daemon_install_call().unwrap();
    assert_eq!(calls, 1);
    assert_eq!(
        std::fs::canonicalize(&daemon_source).unwrap(),
        std::fs::canonicalize(&archive).unwrap()
    );
    assert!(
        load_lock(&principal, "demo").await.unwrap().is_none(),
        "an arbitrary local capsule remains local"
    );
}

#[tokio::test]
async fn station_flags_must_be_supplied_as_a_pair() {
    let root = tempfile::tempdir().unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, archive) = capsule_archive(manifest);
    let lock = lock_for_archive(&archive, manifest);
    let lock_path = root.path().join("pair.lock.json");
    write_lock_json(&lock_path, &lock);
    let digest_value = lock_file_sha256(&lock_path);
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _lock_backend = super::test_lock_backend::install().await;
    for (lock, sha) in [
        (Some(lock_path.as_path()), None),
        (None, Some(digest_value.as_str())),
    ] {
        let error =
            crate::commands::capsule::install::install_capsule_with_options_and_station_lock_in_home(
                &crate::commands::capsule::install::StationInstallRequest {
                    source: archive.to_str().unwrap(),
                    capsule: None,
                    workspace: false,
                    yes: true,
                    approve_untrusted: false,
                    station_lock: lock,
                    station_lock_sha256: sha,
                    vars: &[],
                },
                &home,
            )
            .await
            .expect_err("either handoff flag alone must fail closed");
        assert!(
            error
                .to_string()
                .contains("--station-lock and --station-lock-sha256"),
            "unexpected paired-argument error: {error}"
        );
    }
    assert_eq!(super::test_lock_backend::set_calls(), 0);
}

#[test]
fn station_install_remove_local_install_does_not_reresolve_station() {
    let principal = PrincipalId::default();
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let astrid_home = root.path().join("astrid");
    let workspace_root = root.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let lock = lock_for_archive(&fixture, manifest);
    let lock_json = root.path().join("resolved.lock.json");
    write_lock_json(&lock_json, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker, &lock_json);

    // The production adapter reads these process settings. Keep the fixture
    // isolated from the operator's Station home and binary.
    let _current_dir = CurrentDirGuard::install(&workspace_root);
    let _station_paths = super::test_station_paths(&script, &station_home);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _lock_backend = runtime.block_on(super::test_lock_backend::install());
    let prompt = ManualInstallOptions {
        yes: true,
        approve_untrusted: true,
        ..Default::default()
    };

    // Station install: production coordinate adapter resolves/fetches, stages
    // privately, persists the typed lock, and invokes the normal local
    // installer. This is deliberately not a hand-rolled store_lock step.
    let installed = runtime
        .block_on(
            crate::commands::capsule::install::test_install_station_source(
                "@official/demo",
                &astrid_core::dirs::AstridHome::from_path(&astrid_home),
                &principal,
                &prompt,
            ),
        )
        .unwrap();
    assert_eq!(installed[0].id.as_str(), "demo");
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_some()
    );
    let after_install = std::fs::read_to_string(&marker).unwrap();
    assert!(after_install.contains("resolve"));
    assert!(after_install.contains("fetch"));

    // Production workspace removal deletes the installed capsule and invokes
    // its readiness-gated Station lock clear call site.
    test_remove_capsule_from_home_for_in_workspace(
        &astrid_core::dirs::AstridHome::from_path(&astrid_home),
        &principal,
        "demo",
        true,
        Some(&workspace_root),
        true,
        false,
    )
    .unwrap();
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_none()
    );

    // Production local replacement routes through install_capsule_inner and
    // its clear_replaced_station_locks boundary. It records the local source.
    let replaced = runtime
        .block_on(
            crate::commands::capsule::install::test_install_local_source(
                fixture.to_str().unwrap(),
                &astrid_core::dirs::AstridHome::from_path(&astrid_home),
                &principal,
                &prompt,
            ),
        )
        .unwrap();
    assert_eq!(replaced[0].id.as_str(), "demo");
    let after_local = runtime.block_on(load_lock(&principal, "demo")).unwrap();
    assert!(after_local.is_none());

    let rec = show_record(after_local.as_ref());
    assert!(rec.registry_source.is_none());
    let json = serde_json::to_value(&rec).unwrap();
    assert!(json.get("registry_source").is_none());
    assert_eq!(json["source"], "8d5f2f7d-c89f-4d8f-9ac8-4b5e3d7c7b2d");

    // The real update command follows the local source from meta.json. It
    // must not consult Station after the replacement cleared its lock.
    runtime
        .block_on(
            crate::commands::capsule::install_update::test_update_workspace_capsule_in_home(
                "demo",
                &astrid_core::dirs::AstridHome::from_path(&astrid_home),
                &principal,
                true,
            ),
        )
        .unwrap();
    let after_update = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        after_install, after_update,
        "update after local replacement must not re-enter Station"
    );
}

#[test]
fn station_local_replacement_clears_live_lock_before_update_and_show() {
    let principal = PrincipalId::default();
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let astrid_home = root.path().join("astrid");
    let workspace_root = root.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let lock = lock_for_archive(&fixture, manifest);
    let lock_json = root.path().join("resolved.lock.json");
    write_lock_json(&lock_json, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker, &lock_json);

    let _current_dir = CurrentDirGuard::install(&workspace_root);
    let _station_paths = super::test_station_paths(&script, &station_home);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _lock_backend = runtime.block_on(super::test_lock_backend::install());
    let prompt = ManualInstallOptions {
        yes: true,
        approve_untrusted: true,
        ..Default::default()
    };
    let home = astrid_core::dirs::AstridHome::from_path(&astrid_home);

    let installed = runtime
        .block_on(
            crate::commands::capsule::install::test_install_station_source(
                "@official/demo",
                &home,
                &principal,
                &prompt,
            ),
        )
        .unwrap();
    assert_eq!(installed[0].id.as_str(), "demo");
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_some(),
        "Station install must leave live provenance for replacement to clear"
    );
    let after_station_install = std::fs::read_to_string(&marker).unwrap();

    let replaced = runtime
        .block_on(
            crate::commands::capsule::install::test_install_local_source(
                fixture.to_str().unwrap(),
                &home,
                &principal,
                &prompt,
            ),
        )
        .unwrap();
    assert_eq!(replaced[0].id.as_str(), "demo");
    let after_local = runtime.block_on(load_lock(&principal, "demo")).unwrap();
    assert!(
        after_local.is_none(),
        "production local replacement must clear live Station provenance"
    );

    let record = show_record(after_local.as_ref());
    assert!(record.registry_source.is_none());
    assert!(
        serde_json::to_value(&record).unwrap()["registry_source"].is_null(),
        "show must not expose the replaced Station identity"
    );

    runtime
        .block_on(
            crate::commands::capsule::install_update::test_update_workspace_capsule_in_home(
                "demo", &home, &principal, true,
            ),
        )
        .unwrap();
    assert_eq!(
        after_station_install,
        std::fs::read_to_string(&marker).unwrap(),
        "update after local replacement must not re-enter Station"
    );
}

#[tokio::test]
async fn bare_hex_manifest_is_canonicalized_before_lock_set_and_update_from_lock() {
    let _lock_backend = super::test_lock_backend::install().await;
    let principal = PrincipalId::new("alice").unwrap();
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let hex = domain_digest(manifest);
    let mut lock = lock_for_archive(&fixture, manifest);
    lock.publication_digest = hex::encode([0x22_u8; 32]);
    let artifact_blake3 = lock.artifact_blake3.clone();
    lock.artifact_blake3 = artifact_blake3.strip_prefix("blake3:").unwrap().to_owned();
    let lock_json = root.path().join("resolved.lock.json");
    write_lock_json(&lock_json, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker, &lock_json);

    let mut malformed = lock.clone();
    malformed.manifest_digest = format!("sha256:{hex}");
    assert!(
        resolve_and_fetch_at("", None, Some(&malformed), &script, &station_home).is_err(),
        "wrong digest algorithm must fail before fetch/handoff"
    );
    assert!(
        !marker.exists() || std::fs::read_to_string(&marker).unwrap().is_empty(),
        "malformed lock must not reach Station fetch"
    );

    store_lock(&principal, "demo", lock.clone()).await.unwrap();
    let persisted = load_lock(&principal, "demo")
        .await
        .unwrap()
        .expect("canonical lock");
    assert_eq!(persisted.manifest_digest, format!("blake3:{hex}"));
    assert_eq!(persisted.publication_digest, digest("blake3:", 0x22));
    assert_eq!(persisted.artifact_blake3, artifact_blake3);
    assert!(persisted.manifest_digest.starts_with("blake3:"));

    let artifact =
        resolve_and_fetch_at("", None, Some(&persisted), &script, &station_home).unwrap();
    let calls = std::fs::read_to_string(&marker).unwrap();
    assert!(calls.contains("fetch"));
    assert!(calls.contains("--lock"));
    assert!(!calls.contains(" resolve "));
    assert_eq!(artifact.lock.manifest_digest, format!("blake3:{hex}"));
    assert_eq!(artifact.lock.publication_digest, digest("blake3:", 0x22));
    store_lock(&principal, "demo", artifact.lock.clone())
        .await
        .unwrap();
    let round_trip = load_lock(&principal, "demo")
        .await
        .unwrap()
        .expect("updated lock");
    assert_eq!(round_trip.manifest_digest, format!("blake3:{hex}"));
}
