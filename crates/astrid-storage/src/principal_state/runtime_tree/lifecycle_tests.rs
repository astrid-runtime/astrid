//! Public open/pack/reopen coverage for rooted runtime restoration.
//!
//! Volume-authored projection content is packed to a volume-only home, reopened
//! to materialize nested paths, repeat-packed, and checked for lock/journal or
//! scoped-temp residue. Scoped crash residue is planted only through a bound
//! restoration writer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::platform_fs::is_structural_private_staging_name;

use crate::principal_state::RuntimePrincipalStore;
use crate::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};

const PROFILE: &str = "etc/profiles/campaign/agent.toml";
const PROFILE_BYTES: &[u8] = b"campaign=restoration-lifecycle\n";
const MARKER: &str = "etc/restoration-lifecycle.marker";
const MARKER_BYTES: &[u8] = b"marker-v1\n";
const ROOT_MARKER: &str = "restoration-lifecycle.root";
const ROOT_BYTES: &[u8] = b"root-v1\n";
const PRIVATE_LOCK: &str = ".astrid-private-write.lock";
const PRIVATE_JOURNAL: &str = ".astrid-private-write.transaction.json";

fn fixture() -> (tempfile::TempDir, AstridHome) {
    #[cfg(windows)]
    let root = tempfile::Builder::new()
        .prefix("astrid-restoration-")
        .tempdir_in(directories::BaseDirs::new().unwrap().data_local_dir())
        .unwrap();
    #[cfg(not(windows))]
    let root = tempfile::tempdir().unwrap();
    // Let production create the private home at birth. The TempDir only owns
    // the fixture's parent; it is never an existing non-private runtime root.
    let home = AstridHome::from_path(root.path().join("home"));
    home.ensure().unwrap();
    (root, home)
}

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn name(path: &str) -> ContentName {
    ContentName::new(path).unwrap()
}

fn put_volume(store: &RuntimePrincipalStore, path: &str, bytes: &[u8]) {
    store
        .content()
        .put(&StateOwner::System, &name(path), bytes)
        .unwrap();
}

fn assert_volume_bytes(store: &RuntimePrincipalStore, path: &str, bytes: &[u8]) {
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name(path))
            .unwrap(),
        Some(bytes.to_vec()),
        "volume readback mismatch for {path}"
    );
}

fn assert_host_bytes(home: &AstridHome, path: &str, bytes: &[u8]) {
    assert_eq!(
        std::fs::read(home.root().join(path)).unwrap(),
        bytes,
        "host materialization mismatch for {path}"
    );
}

fn assert_projection(home: &AstridHome, store: &RuntimePrincipalStore) {
    assert_host_bytes(home, PROFILE, PROFILE_BYTES);
    assert_host_bytes(home, MARKER, MARKER_BYTES);
    assert_host_bytes(home, ROOT_MARKER, ROOT_BYTES);
    assert_volume_bytes(store, PROFILE, PROFILE_BYTES);
    assert_volume_bytes(store, MARKER, MARKER_BYTES);
    assert_volume_bytes(store, ROOT_MARKER, ROOT_BYTES);
}

fn assert_volume_only(home: &AstridHome) {
    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1, "stopped home must keep only the volume");
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new(super::CANONICAL_VOLUME)
    );
}

fn collect_forbidden(root: &Path) -> Vec<PathBuf> {
    let mut bad = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let file_name = entry.file_name();
            let lower = file_name.to_string_lossy().to_ascii_lowercase();
            if lower == PRIVATE_LOCK
                || lower == PRIVATE_JOURNAL
                || lower.starts_with(".astrid-private.")
                || is_structural_private_staging_name(&file_name)
            {
                bad.push(path.clone());
            }
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    bad
}

fn assert_no_projection_residue(home: &AstridHome) {
    let bad = collect_forbidden(home.root());
    assert!(
        bad.is_empty(),
        "unexpected lock/journal/scoped residue: {bad:?}"
    );
}

async fn open_store(home: &AstridHome) -> RuntimePrincipalStore {
    open_runtime_principal_store(home, quota()).await.unwrap()
}

fn seed_volume_projection(store: &RuntimePrincipalStore) {
    put_volume(store, PROFILE, PROFILE_BYTES);
    put_volume(store, MARKER, MARKER_BYTES);
    put_volume(store, ROOT_MARKER, ROOT_BYTES);
    store.content().flush().unwrap();
}

#[tokio::test]
async fn public_pack_reopen_repeat_materializes_nested_profile_without_residue() {
    let (_root, home) = fixture();

    let store = open_store(&home).await;
    seed_volume_projection(&store);
    assert_volume_bytes(&store, PROFILE, PROFILE_BYTES);
    assert!(!home.root().join(PROFILE).exists());

    store.publish_runtime_projection(&home).unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    assert_volume_only(&home);
    assert_no_projection_residue(&home);

    for _ in 0..2 {
        let store = open_store(&home).await;
        assert_projection(&home, &store);
        assert_no_projection_residue(&home);
        store.pack_and_retire_runtime_projection(&home).unwrap();
        drop(store);
        assert_volume_only(&home);
        assert_no_projection_residue(&home);
    }
}

#[tokio::test]
async fn scoped_staging_crash_residue_discharges_on_public_reopen() {
    let (_root, home) = fixture();

    let store = open_store(&home).await;
    seed_volume_projection(&store);
    store.publish_runtime_projection(&home).unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);

    let store = open_store(&home).await;
    assert_projection(&home, &store);

    let mut prepared = super::restoration::record_intent(&home, &store).unwrap();
    prepared.ensure_scoped_intent().unwrap();
    let scope = prepared
        .staging_scope()
        .expect("schema-2 restoration intent mints a durable scope");
    let basename = scope.temporary_basename();
    let root_rel = PathBuf::from(&basename);
    let etc_rel = Path::new("etc").join(&basename);
    let nested_rel = Path::new("etc/profiles/campaign").join(&basename);

    {
        let writer = prepared.writer().expect("bound restoration writer");
        writer
            .write(Path::new(MARKER), b"host mutation before crash\n")
            .unwrap();
        writer.write(&root_rel, b"scoped root residue").unwrap();
        writer.write(&etc_rel, b"scoped etc residue").unwrap();
        writer.write(&nested_rel, b"scoped nested residue").unwrap();
        writer.sync().unwrap();
    }

    let root_temp = home.root().join(&root_rel);
    let etc_temp = home.root().join(&etc_rel);
    let nested_temp = home.root().join(&nested_rel);
    assert!(root_temp.is_file());
    assert!(etc_temp.is_file());
    assert!(nested_temp.is_file());
    drop(prepared);
    drop(store);

    let store = open_store(&home).await;
    assert!(!root_temp.exists(), "root scoped temp must discharge");
    assert!(!etc_temp.exists(), "etc scoped temp must discharge");
    assert!(!nested_temp.exists(), "nested scoped temp must discharge");
    assert_projection(&home, &store);
    assert_no_projection_residue(&home);
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    assert_volume_only(&home);
    assert_no_projection_residue(&home);
}
