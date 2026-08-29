//! Production regressions for the Station-bound install transaction.
//!
//! These tests exercise real signed archives end to end against an isolated
//! `AstridHome`: the concurrent-install barrier, caller-path substitution
//! resistance, and the invariant that ordinary installs never persist a
//! Station lock.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::station::stage_gate;
use super::{InstallCapsuleRequest, handle_install_capsule};
use crate::kernel_router::admin::{station_handlers, station_store};
use crate::test_kernel_with_home;
use astrid_build::artifact::sign_archive;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{
    AdminResponseBody, CapsuleInstallAuthority, CapsuleInstallProvenance, KernelResponse,
    StationCoordinate, StationInstallBinding, StationLock,
};
use astrid_core::{PrincipalId, identity::PrincipalUid};
use astrid_crypto::KeyPair;
use sha2::Digest as _;

struct Fixture {
    dir: tempfile::TempDir,
    kernel: Arc<crate::Kernel>,
    principal: PrincipalId,
    key: KeyPair,
}

async fn fixture(principal_name: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let home_root = dir.path().join("astrid-home");
    std::fs::create_dir_all(&home_root).unwrap();
    let key = KeyPair::generate();
    let home = AstridHome::from_path(&home_root);
    let kernel = test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::new(principal_name).unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            &home, &principal,
        ))
        .unwrap();
    std::fs::create_dir_all(home.keys_dir()).unwrap();
    std::fs::write(home.runtime_key_path(), key.secret_key_bytes()).unwrap();
    kernel
        .principal_directory
        .register(principal.clone(), PrincipalUid::from_bytes([0x42; 32]))
        .unwrap();
    Fixture {
        dir,
        kernel,
        principal,
        key,
    }
}

fn write_unsigned_archive(path: &Path, name: &str, version: &str) {
    let manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\n\
         [capabilities]\nnet_connect = [\"api.example:443\"]\n"
    );
    let file = std::fs::File::create(path).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "Capsule.toml", manifest.as_bytes())
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();
}

fn shaped_lock(name: &str, version: &str, bytes: &[u8]) -> StationLock {
    StationLock {
        schema: station_store::LOCK_SCHEMA_V2.to_owned(),
        station_id: "official".to_owned(),
        trust_root: format!("sha256:{}", hex::encode([7_u8; 32])),
        coordinate: StationCoordinate {
            namespace: "official".to_owned(),
            name: name.to_owned(),
        },
        version: version.to_owned(),
        publication_digest: format!("blake3:{}", hex::encode([8_u8; 32])),
        artifact_size: bytes.len() as u64,
        artifact_media_type: "application/vnd.astrid.capsule".to_owned(),
        artifact_sha256: format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes))),
        artifact_blake3: format!("blake3:{}", blake3::hash(bytes).to_hex()),
        manifest_digest: format!("blake3:{}", hex::encode([9_u8; 32])),
        capsule_content_digest: format!("blake3:{}", hex::encode([10_u8; 32])),
        package_digest: format!("blake3:{}", hex::encode([11_u8; 32])),
        component_count: 0,
        component_digest: format!("blake3:{}", hex::encode([12_u8; 32])),
        wit_digest: format!("blake3:{}", hex::encode([13_u8; 32])),
        capability_digest: format!("blake3:{}", hex::encode([14_u8; 32])),
        ipc_digest: format!("blake3:{}", hex::encode([15_u8; 32])),
        runtime_abi_digest: format!("blake3:{}", hex::encode([16_u8; 32])),
        dependency_digest: format!("blake3:{}", hex::encode([17_u8; 32])),
        provenance_digest: format!("blake3:{}", hex::encode([18_u8; 32])),
        source_digest: format!("blake3:{}", hex::encode([19_u8; 32])),
    }
}

struct BoundArchive {
    path: PathBuf,
    binding: StationInstallBinding,
}

impl BoundArchive {
    fn expecting(mut self, expected_hash: Option<String>) -> Self {
        self.binding.expected_hash = expected_hash;
        self
    }
}

fn bound_archive(fixture: &Fixture, name: &str, version: &str) -> BoundArchive {
    let archive_path = fixture.dir.path().join(format!("{name}-{version}.capsule"));
    write_unsigned_archive(&archive_path, name, version);
    sign_archive(&archive_path, &fixture.key).unwrap();
    let bytes = std::fs::read(&archive_path).unwrap();
    BoundArchive {
        path: archive_path,
        binding: StationInstallBinding {
            capsule: name.to_owned(),
            lock: Box::new(shaped_lock(name, version, &bytes)),
            expected_hash: None,
        },
    }
}

#[allow(clippy::ref_option)]
fn request<'a>(
    fixture: &'a Fixture,
    source: &'a Path,
    binding: &'a Option<StationInstallBinding>,
) -> InstallCapsuleRequest<'a> {
    InstallCapsuleRequest {
        caller: &fixture.principal,
        requested_target: None,
        source: source.to_str().unwrap(),
        workspace: false,
        provenance: None::<&'a CapsuleInstallProvenance>,
        authority: CapsuleInstallAuthority::Automatic,
        env: &[],
        station_binding: binding,
    }
}

async fn stored_lock(fixture: &Fixture, capsule: &str) -> Option<StationLock> {
    match station_handlers::get(&fixture.kernel, &fixture.principal, capsule).await {
        AdminResponseBody::StationLock(lock) => *lock,
        other => panic!("unexpected Station lock read: {other:?}"),
    }
}

async fn seed_prior_lock(fixture: &Fixture, capsule: &str, lock: &StationLock) -> String {
    let encoded = station_store::encode_lock(lock).unwrap();
    let store =
        station_store::principal_control_store(&fixture.kernel, &fixture.principal).unwrap();
    store.set(capsule, encoded).await.unwrap();
    station_store::digest_bytes(&serde_json::to_vec(lock).unwrap())
}

fn package_sibling_names(target_dir: &Path) -> Vec<String> {
    let parent = target_dir.parent().unwrap_or(target_dir);
    let mut names: Vec<String> = std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn identical_expectations_serialize_to_a_single_valid_winner() {
    let fixture = fixture("barrier-owner").await;
    let prior = shaped_lock("barrier-demo", "0.9.0", b"prior-state");
    let shared_expected = seed_prior_lock(&fixture, "barrier-demo", &prior).await;

    let winner =
        bound_archive(&fixture, "barrier-demo", "1.1.0").expecting(Some(shared_expected.clone()));
    let loser = bound_archive(&fixture, "barrier-demo", "2.0.0").expecting(Some(shared_expected));

    let winner_binding = Some(winner.binding);
    let winner_response = handle_install_capsule(
        &fixture.kernel,
        request(&fixture, &winner.path, &winner_binding),
    )
    .await;
    let winner_target_dir = match winner_response {
        KernelResponse::Success(value) => {
            let target_dir = value["target_dir"]
                .as_str()
                .expect("install output target_dir")
                .to_owned();
            assert!(Path::new(&target_dir).join("Capsule.toml").exists());
            target_dir
        },
        other => panic!("valid winner install failed: {other:?}"),
    };
    let siblings_before = package_sibling_names(Path::new(&winner_target_dir));

    let loser_binding = Some(loser.binding);
    let loser_response = handle_install_capsule(
        &fixture.kernel,
        request(&fixture, &loser.path, &loser_binding),
    )
    .await;
    match loser_response {
        KernelResponse::Error(message) => {
            assert!(message.contains("changed"), "{message}");
            assert!(!message.contains("2.0.0"), "{message}");
        },
        other => panic!("stale expectation unexpectedly succeeded: {other:?}"),
    }

    assert_eq!(
        package_sibling_names(Path::new(&winner_target_dir)),
        siblings_before,
        "the serialized loser must not leave a package behind"
    );
    let committed = stored_lock(&fixture, "barrier-demo").await.unwrap();
    assert_eq!(
        committed.version, "1.1.0",
        "only the serialized valid winner may leave a durable pair"
    );
}

#[tokio::test]
async fn substituted_caller_path_cannot_change_verified_installed_bytes() {
    let fixture = fixture("substitution-owner").await;
    let bound = bound_archive(&fixture, "swap-demo", "3.1.4");
    let original_size = bound.binding.lock.artifact_size;
    let original_blake3 = bound.binding.lock.artifact_blake3.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    stage_gate::arm(rx);

    let kernel = Arc::clone(&fixture.kernel);
    let principal = fixture.principal.clone();
    let binding = Some(bound.binding);
    let source = bound.path.clone();
    let source_text = source.to_string_lossy().into_owned();
    let install_task = tokio::spawn(async move {
        handle_install_capsule(
            &kernel,
            InstallCapsuleRequest {
                caller: &principal,
                requested_target: None,
                source: &source_text,
                workspace: false,
                provenance: None,
                authority: CapsuleInstallAuthority::Automatic,
                env: &[],
                station_binding: &binding,
            },
        )
        .await
    });

    tx.send(()).unwrap();
    let evil_path = fixture.dir.path().join("evil.capsule");
    std::fs::write(&evil_path, b"attacker bytes attacker bytes").unwrap();
    std::fs::remove_file(&source).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&evil_path, &source).unwrap();

    match install_task.await.unwrap() {
        KernelResponse::Success(value) => {
            let target_dir = PathBuf::from(value["target_dir"].as_str().unwrap());
            let installed_manifest =
                std::fs::read_to_string(target_dir.join("Capsule.toml")).unwrap();
            assert!(
                installed_manifest.contains("version = \"3.1.4\""),
                "installed bytes must be the originally authorized artifact"
            );
            let committed = stored_lock(&fixture, "swap-demo").await.unwrap();
            assert_eq!(committed.artifact_size, original_size);
            assert_eq!(committed.artifact_blake3, original_blake3);
        },
        KernelResponse::Error(message) => {
            assert!(
                stored_lock(&fixture, "swap-demo").await.is_none(),
                "{message}"
            );
        },
        other => panic!("unexpected response frame: {other:?}"),
    }
}

#[tokio::test]
async fn absent_expectation_rejects_existing_prior_state() {
    let fixture = fixture("absence-owner").await;
    let prior = shaped_lock("absence-demo", "7.7.7", b"existing");
    seed_prior_lock(&fixture, "absence-demo", &prior).await;

    let corrupt = fixture.dir.path().join("corrupt.capsule");
    std::fs::write(&corrupt, b"not a capsule").unwrap();
    let create_only = Some(StationInstallBinding {
        capsule: "absence-demo".to_owned(),
        lock: Box::new(prior),
        expected_hash: None,
    });
    let response =
        handle_install_capsule(&fixture.kernel, request(&fixture, &corrupt, &create_only)).await;
    match response {
        KernelResponse::Error(message) => {
            assert!(message.contains("already exists"), "{message}");
        },
        other => panic!("create semantics over existing state accepted: {other:?}"),
    }
}

#[tokio::test]
async fn ordinary_installs_leave_no_station_lock_even_when_failing() {
    let fixture = fixture("ordinary-owner").await;
    let plain = bound_archive(&fixture, "plain-demo", "9.9.9");
    let no_binding: Option<StationInstallBinding> = None;
    let response =
        handle_install_capsule(&fixture.kernel, request(&fixture, &plain.path, &no_binding)).await;
    assert!(matches!(response, KernelResponse::Success(_)));
    assert!(stored_lock(&fixture, "plain-demo").await.is_none());

    let broken = fixture.dir.path().join("broken.capsule");
    std::fs::write(&broken, b"definitely not a capsule").unwrap();
    let failed =
        handle_install_capsule(&fixture.kernel, request(&fixture, &broken, &no_binding)).await;
    assert!(matches!(failed, KernelResponse::Error(_)));
    assert!(stored_lock(&fixture, "broken-demo").await.is_none());
    assert!(stored_lock(&fixture, "plain-demo").await.is_none());
}
