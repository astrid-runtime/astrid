//! Public-path checks for the offline recovery benchmark and its phase evidence.
#![allow(dead_code)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use astrid_core::dirs::AstridHome;
use astrid_storage::engine::{DurableEngine, RecoveryLimits};
use astrid_storage::volume::HostedFileVolume;
use astrid_storage::{
    Blake3ObjectIdentityV1, DurableEnginePolicy, StateOwner, StateOwnerCodecV2,
    open_runtime_principal_store,
};
use tracing_subscriber::fmt::format::FmtSpan;

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
#[path = "../benches/storage_io/config.rs"]
mod config;
#[path = "../benches/storage_io/provenance.rs"]
mod provenance;
#[path = "../benches/storage_io/recovery.rs"]
mod recovery;
#[path = "../benches/storage_io/report.rs"]
mod report;

async fn fixture(path: &Path) -> PathBuf {
    let home = AstridHome::from_path(path.to_path_buf());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, Arc::new(|_: &StateOwner| Ok(None)))
        .await
        .unwrap();
    store
        .kv()
        .set("system:benchmark", "known", b"persisted".to_vec())
        .await
        .unwrap();
    store.kv().close().await.unwrap();
    drop(store);
    home.storage_volume_path()
}

#[tokio::test]
async fn repeats_identical_snapshot_and_keeps_source_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let source_path = fixture(&tmp.path().join("source")).await;
    let original = std::fs::read(&source_path).unwrap();
    let mut source = recovery::FrozenSource::open(&source_path).unwrap();
    let mut expected = None;
    for index in 0..2 {
        let path = tmp.path().join(format!("copy-{index}"));
        source.copy_to(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let volume = HostedFileVolume::open(&path).unwrap();
        let engine = DurableEngine::open_volume(
            volume,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            DurableEnginePolicy::default(),
        )
        .unwrap();
        let roots = engine.roots().unwrap();
        assert!(!roots.is_empty());
        if let Some(expected) = &expected {
            assert_eq!(expected, &roots);
        } else {
            expected = Some(roots);
        }
        engine.close().unwrap();
    }
    source.verify().unwrap();
    assert_eq!(std::fs::read(source_path).unwrap(), original);
}

#[test]
fn source_writer_lock_and_existing_destination_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("source");
    std::fs::write(&path, b"source bytes").unwrap();
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&writer).unwrap();
    assert!(recovery::FrozenSource::open(&path).is_err());
    drop(writer);
    let mut source = recovery::FrozenSource::open(&path).unwrap();
    let destination = tmp.path().join("existing");
    std::fs::write(&destination, b"do not overwrite").unwrap();
    assert!(source.copy_to(&destination).is_err());
    assert_eq!(std::fs::read(destination).unwrap(), b"do not overwrite");
}

#[derive(Clone)]
struct EvidenceWriter(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for EvidenceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn profile_emits_actual_recovery_boundaries_and_counts() {
    // Callsite interest is process-wide. Other parallel tests intentionally
    // exercise these functions without a subscriber; isolate the measurement.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "isolated_recovery_profile",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("running 1 test")
            && stdout.contains("test isolated_recovery_profile ... ok")
            && !stdout.contains("running 0 tests"),
        "isolated profile assertions did not execute: {stdout}"
    );
}

#[tokio::test]
#[ignore = "executed by profile_emits_actual_recovery_boundaries_and_counts in a private process"]
async fn isolated_recovery_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let path = fixture(&tmp.path().join("source")).await;
    let copy = tmp.path().join("profile.volume");
    recovery::FrozenSource::open(&path)
        .unwrap()
        .copy_to(&copy)
        .unwrap();
    let output = EvidenceWriter(Arc::default());
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("astrid_storage::recovery=debug")
        .with_span_events(FmtSpan::CLOSE)
        .json()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let volume = HostedFileVolume::open(copy).unwrap();
        let engine = DurableEngine::open_volume(
            volume,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            DurableEnginePolicy::default(),
        )
        .unwrap();
        engine.close().unwrap();
    });
    let bytes = output.0.lock().unwrap().clone();
    let records = String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    for phase in [
        "open",
        "open_volume_engine",
        "recover_representations",
        "reconstruct_active_representations",
        "validate_representation_index",
        "recover_metadata",
        "recover_journal",
        "recover_active_map",
        "validate_profiles",
        "validate_representations",
        "recover_volume_index",
        "recover_roots",
    ] {
        assert!(
            records
                .iter()
                .any(|r| r["span"]["name"] == phase && r["fields"]["time.busy"].is_string()),
            "missing measured phase {phase}: {records:?}"
        );
    }
    assert!(
        records
            .iter()
            .any(|r| r["span"]["name"] == "recover_metadata"
                && r["span"]["map_nodes"].as_u64().is_some_and(|n| n > 0))
    );
    assert!(
        records
            .iter()
            .any(|r| r["span"]["name"] == "recover_journal"
                && r["span"]["journal_frames"].as_u64().is_some_and(|n| n > 0))
    );
}

#[test]
fn invalid_snapshot_is_rejected_without_modifying_source() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("invalid-source");
    let original = b"not an Astrid volume";
    std::fs::write(&path, original).unwrap();
    let mut source = recovery::FrozenSource::open(&path).unwrap();
    let copy = tmp.path().join("copy");
    source.copy_to(&copy).unwrap();
    assert!(HostedFileVolume::open(copy).is_err());
    source.verify().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), original);
}
