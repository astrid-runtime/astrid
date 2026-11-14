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

pub(super) fn fixture() -> (tempfile::TempDir, AstridHome) {
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

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn public_reopen_respects_target_case_equivalence_before_host_mutation() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let lower = "case-collision.toml";
    let upper = "CASE-COLLISION.TOML";
    put_volume(&store, lower, b"lower generation");
    put_volume(&store, upper, b"upper generation");
    store.content().flush().unwrap();
    drop(store);
    // Proven case-sensitive parents may keep both spellings. Caseless parents
    // and indeterminate queries must fail closed before host mutation while
    // both durable values remain pack-readable.
    let allow_distinct = astrid_core::platform_fs::directory_is_case_sensitive(home.root())
        .ok()
        .is_some_and(|case_sensitive| case_sensitive);
    let reopened = open_runtime_principal_store(&home, quota()).await;
    if allow_distinct {
        let store = reopened.unwrap();
        assert_host_bytes(&home, lower, b"lower generation");
        assert_host_bytes(&home, upper, b"upper generation");
        assert_volume_bytes(&store, lower, b"lower generation");
        assert_volume_bytes(&store, upper, b"upper generation");
    } else {
        let error = reopened
            .err()
            .expect("target namespace aliases must fail before publication");
        let message = error.to_string();
        assert!(
            message.contains("projection namespace collision")
                || message.contains("query target namespace"),
            "{error}"
        );
        assert!(!home.root().join(lower).exists());
        assert!(!home.root().join(upper).exists());
        let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
            .await
            .unwrap();
        assert_volume_bytes(&packed, lower, b"lower generation");
        assert_volume_bytes(&packed, upper, b"upper generation");
    }
}

#[tokio::test]
async fn public_reopen_rejects_backslash_projection_spelling_before_host_mutation() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let slash = "dir/file";
    let backslash = "dir\\file";
    put_volume(&store, slash, b"slash generation");
    put_volume(&store, backslash, b"backslash generation");
    store.content().flush().unwrap();
    drop(store);

    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("non-canonical backslash spelling must fail before publication");
    let message = error.to_string();
    assert!(
        message.contains("canonical host spelling")
            || message.contains("projection namespace collision"),
        "{error}"
    );
    assert!(!home.root().join("dir").join("file").exists());
    assert!(!home.root().join(slash).exists());

    let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
        .await
        .unwrap();
    assert_volume_bytes(&packed, slash, b"slash generation");
    assert_volume_bytes(&packed, backslash, b"backslash generation");
}

fn volume_identity(home: &AstridHome) -> (blake3::Hash, same_file::Handle) {
    let path = home.root().join(super::CANONICAL_VOLUME);
    let digest = blake3::hash(&std::fs::read(&path).expect("fixture volume bytes"));
    let handle = same_file::Handle::from_path(&path).expect("volume same_file handle");
    (digest, handle)
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn public_reopen_rejects_volume_sentinel_alias_before_host_mutation() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let impostor = "ASTRID.VOLUME";
    let payload = b"impostor volume alias generation\n";
    put_volume(&store, impostor, payload);
    store.content().flush().unwrap();
    drop(store);

    let (digest_before, handle_before) = volume_identity(&home);
    let allow_distinct = astrid_core::platform_fs::directory_is_case_sensitive(home.root())
        .ok()
        .is_some_and(|case_sensitive| case_sensitive);

    let reopened = open_runtime_principal_store(&home, quota()).await;
    if allow_distinct {
        let store = reopened.expect("case-sensitive root may keep distinct volume spelling");
        assert_host_bytes(&home, impostor, payload);
        assert_volume_bytes(&store, impostor, payload);
        let (_, handle_after) = volume_identity(&home);
        // A successful reopen may append legitimate projection bookkeeping.
        assert_eq!(
            handle_before, handle_after,
            "open volume inode must survive distinct admit"
        );
    } else {
        let error = reopened
            .err()
            .expect("caseless volume sentinel alias must fail before publication");
        let message = error.to_string();
        assert!(
            message.contains("projection namespace collision")
                || message.contains("query target namespace"),
            "{error}"
        );
        assert_eq!(
            same_file::Handle::from_path(home.root().join(impostor)).unwrap(),
            handle_before,
            "caseless spelling must still address the original volume"
        );
        let (digest_after, handle_after) = volume_identity(&home);
        assert_eq!(
            digest_before, digest_after,
            "volume bytes must survive rejected reopen"
        );
        assert_eq!(
            handle_before, handle_after,
            "open volume inode must survive rejected reopen"
        );

        let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
            .await
            .unwrap();
        assert_volume_bytes(&packed, impostor, payload);
    }
}

#[tokio::test]
async fn public_reopen_rejects_volume_directory_marker_before_host_mutation() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let marker = "astrid.volume/";
    let payload = b"volume directory marker generation\n";
    put_volume(&store, marker, payload);
    store.content().flush().unwrap();
    drop(store);

    let (digest_before, handle_before) = volume_identity(&home);
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("volume directory marker must fail before publication");
    let message = error.to_string();
    assert!(
        message.contains("projection namespace collision"),
        "{error}"
    );
    assert!(
        !home.root().join("astrid.volume").is_dir(),
        "volume must remain the open file, not a restored directory marker"
    );
    let (digest_after, handle_after) = volume_identity(&home);
    assert_eq!(digest_before, digest_after);
    assert_eq!(handle_before, handle_after);

    let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
        .await
        .unwrap();
    assert_volume_bytes(&packed, marker, payload);
}

#[cfg(windows)]
#[tokio::test]
async fn public_reopen_rejects_windows_ads_projection_spelling_before_host_mutation() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let plain = "dir/file";
    let ads = "dir/file::$DATA";
    put_volume(&store, plain, b"plain generation");
    put_volume(&store, ads, b"ads generation");
    store.content().flush().unwrap();
    drop(store);

    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("Windows ADS spelling must fail before publication");
    let message = error.to_string();
    assert!(message.contains("canonical host spelling"), "{error}");
    assert!(!home.root().join("dir").join("file").exists());

    let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
        .await
        .unwrap();
    assert_volume_bytes(&packed, plain, b"plain generation");
    assert_volume_bytes(&packed, ads, b"ads generation");
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn public_reopen_rejects_protected_exclusion_aliases_before_host_mutation() {
    struct Case {
        impostor: &'static str,
        payload: &'static [u8],
        /// When false, caseless roots must reject; case-sensitive may admit.
        must_reject_when_caseless: bool,
    }

    let cases = [
        Case {
            impostor: "RUN/SYSTEM.SOCK",
            payload: b"socket path alias generation\n",
            must_reject_when_caseless: true,
        },
        Case {
            impostor: "VAR/PRINCIPAL-STORE/x",
            payload: b"principal-store alias generation\n",
            must_reject_when_caseless: true,
        },
        Case {
            impostor: "RUN/.ACTIVE-PROJECTION-V1.JSON",
            payload: b"active receipt alias generation\n",
            must_reject_when_caseless: true,
        },
        Case {
            impostor: "VOLUME/hostile",
            payload: b"volume child alias generation\n",
            must_reject_when_caseless: true,
        },
        // Positive: unrelated ancestor siblings must not be claimed by leaf seeds.
        Case {
            impostor: "RUN/capsules/example/component.wasm",
            payload: b"capsule-alias-bytes-v1\n",
            must_reject_when_caseless: false,
        },
        Case {
            impostor: "VAR/unrelated-file",
            payload: b"var sibling bytes\n",
            must_reject_when_caseless: false,
        },
    ];

    for case in cases {
        let (_root, home) = fixture();
        let store = open_store(&home).await;
        put_volume(&store, case.impostor, case.payload);
        store.content().flush().unwrap();
        drop(store);

        let (digest_before, handle_before) = volume_identity(&home);
        let allow_distinct = astrid_core::platform_fs::directory_is_case_sensitive(home.root())
            .ok()
            .is_some_and(|case_sensitive| case_sensitive);
        let reopened = open_runtime_principal_store(&home, quota()).await;

        if !case.must_reject_when_caseless {
            let store = reopened.unwrap_or_else(|error| {
                panic!(
                    "ancestor-sibling projection must remain admissible ({}): {error}",
                    case.impostor
                )
            });
            assert_host_bytes(&home, case.impostor, case.payload);
            assert_volume_bytes(&store, case.impostor, case.payload);
            continue;
        }

        if allow_distinct {
            let store = reopened.unwrap_or_else(|error| {
                panic!(
                    "case-sensitive root should admit distinct exclusion spelling {}: {error}",
                    case.impostor
                )
            });
            assert_volume_bytes(&store, case.impostor, case.payload);
            let (_, handle_after) = volume_identity(&home);
            assert_eq!(handle_before, handle_after, "{}", case.impostor);
            continue;
        }

        let error = reopened.err().unwrap_or_else(|| {
            panic!(
                "caseless protected alias must fail before publication: {}",
                case.impostor
            )
        });
        let message = error.to_string();
        assert!(
            message.contains("projection namespace collision")
                || message.contains("query target namespace"),
            "{}: {error}",
            case.impostor
        );
        let (digest_after, handle_after) = volume_identity(&home);
        assert_eq!(digest_before, digest_after, "{}", case.impostor);
        assert_eq!(handle_before, handle_after, "{}", case.impostor);
        let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
            .await
            .unwrap();
        assert_volume_bytes(&packed, case.impostor, case.payload);
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn public_reopen_rejects_unseeded_run_exclusion_alias_before_host_mutation() {
    // Transient principal scratch is outside projection authority. Its case
    // aliases must not overwrite host state on caseless roots, while distinct
    // spellings on sensitive roots and the capsules exception remain valid.
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let impostor = "RUN/principals/scratch.blob";
    let payload = b"volume-run-principals-alias-v1\n";
    put_volume(&store, impostor, payload);
    store.content().flush().unwrap();
    drop(store);

    let host_rel = "run/principals/scratch.blob";
    let host_bytes = b"host-excluded-principals-scratch-v1\n";
    std::fs::create_dir_all(home.root().join("run/principals")).unwrap();
    std::fs::write(home.root().join(host_rel), host_bytes).unwrap();
    let host_digest = blake3::hash(host_bytes);
    let host_handle =
        same_file::Handle::from_path(home.root().join(host_rel)).expect("host scratch handle");

    let (volume_digest_before, volume_handle_before) = volume_identity(&home);
    let allow_distinct = astrid_core::platform_fs::directory_is_case_sensitive(home.root())
        .ok()
        .is_some_and(|case_sensitive| case_sensitive);
    let reopened = open_runtime_principal_store(&home, quota()).await;

    if allow_distinct {
        let store = reopened.unwrap_or_else(|error| {
            panic!("case-sensitive root may keep distinct RUN/principals spelling: {error}")
        });
        assert_eq!(
            std::fs::read(home.root().join(host_rel)).unwrap(),
            host_bytes,
            "case-sensitive distinct admit must leave excluded run/principals host bytes alone"
        );
        assert_eq!(
            same_file::Handle::from_path(home.root().join(host_rel)).unwrap(),
            host_handle,
            "excluded host inode must survive distinct admit"
        );
        assert_eq!(
            blake3::hash(&std::fs::read(home.root().join(host_rel)).unwrap()),
            host_digest
        );
        assert_host_bytes(&home, impostor, payload);
        assert_volume_bytes(&store, impostor, payload);
        let (_volume_digest_after, volume_handle_after) = volume_identity(&home);
        // Successful reopen may append legitimate projection bookkeeping; keep
        // the open volume file identity, not a frozen pre-reopen content hash.
        assert_eq!(volume_handle_before, volume_handle_after);
        let _ = volume_digest_before;
        return;
    }

    let error = reopened.err().unwrap_or_else(|| {
        panic!("caseless RUN/principals alias must fail before overwriting excluded host path")
    });
    let message = error.to_string();
    assert!(
        message.contains("projection namespace collision")
            || message.contains("query target namespace")
            || message.contains("excluded")
            || message.contains("run/"),
        "unexpected rejection shape: {error}"
    );
    assert_eq!(
        std::fs::read(home.root().join(host_rel)).unwrap(),
        host_bytes,
        "excluded run/principals host bytes must survive rejected reopen"
    );
    assert_eq!(
        same_file::Handle::from_path(home.root().join(host_rel)).unwrap(),
        host_handle,
        "excluded host inode must survive rejected reopen"
    );
    assert_eq!(
        blake3::hash(&std::fs::read(home.root().join(host_rel)).unwrap()),
        host_digest
    );
    let (volume_digest_after, volume_handle_after) = volume_identity(&home);
    assert_eq!(volume_digest_before, volume_digest_after);
    assert_eq!(volume_handle_before, volume_handle_after);

    let packed = crate::principal_state::open_runtime_principal_store_for_pack(&home, quota())
        .await
        .unwrap();
    assert_volume_bytes(&packed, impostor, payload);
}

#[tokio::test]
async fn public_reopen_admits_run_capsules_projection() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    let capsule = "run/capsules/example/component.wasm";
    let payload = b"capsule-bytes-v1\n";
    put_volume(&store, capsule, payload);
    store.content().flush().unwrap();
    drop(store);

    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("run/capsules projections must remain admissible");
    assert_host_bytes(&home, capsule, payload);
    assert_volume_bytes(&store, capsule, payload);
}

#[tokio::test]
async fn public_pack_busy_writer_keeps_host_authority_for_retry() {
    let (_root, home) = fixture();
    let store = open_store(&home).await;
    seed_volume_projection(&store);
    store.content().flush().unwrap();
    drop(store);
    let store = open_store(&home).await;
    store.publish_runtime_projection(&home).unwrap();
    assert_projection(&home, &store);

    // Idle facade/store clones must not block shared revocation. A live writer
    // lease must refuse reserve before host delete.
    let _idle = store.clone();
    let _idle_area = (*store.staging()).clone();
    let writer = store
        .staging()
        .begin(
            StateOwner::System,
            name("var/tmp/held.bin"),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    let error = store
        .pack_and_retire_runtime_projection(&home)
        .expect_err("active writer must refuse staging close");
    assert!(
        error
            .to_string()
            .contains("runtime staging is still in use; stop all staging users before retirement"),
        "{error}"
    );
    assert!(
        store.staging.get().is_some(),
        "busy pack must leave staging installed"
    );
    assert!(home.root().join(PROFILE).is_file());
    store
        .staging()
        .begin(
            StateOwner::System,
            name("var/tmp/busy-still-open.bin"),
            crate::content::ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    drop(writer);

    store.pack_and_retire_runtime_projection(&home).unwrap();
    {
        let area = store.staging();
        let begin_err = area
            .begin(
                StateOwner::System,
                name("var/tmp/after-pack.bin"),
                crate::content::ChunkingProfile::ASTRID_V1,
            )
            .expect_err("post-pack staging begin must error");
        assert!(
            begin_err
                .to_string()
                .contains("runtime staging is closed after projection retirement"),
            "{begin_err}"
        );
        let ready_err = area
            .ready()
            .expect_err("post-pack staging ready must error");
        assert!(
            ready_err
                .to_string()
                .contains("runtime staging is closed after projection retirement"),
            "{ready_err}"
        );
    }
    assert_projection_bytes_via_volume(&store);
    assert_volume_only(&home);
    assert_no_projection_residue(&home);
    store.pack_and_retire_runtime_projection(&home).unwrap();
    let clone = store.clone();
    assert!(
        clone
            .staging()
            .ready()
            .expect_err("cloned closed store must error, not panic")
            .to_string()
            .contains("runtime staging is closed after projection retirement")
    );
}

fn assert_projection_bytes_via_volume(store: &RuntimePrincipalStore) {
    assert_volume_bytes(store, PROFILE, PROFILE_BYTES);
    assert_volume_bytes(store, MARKER, MARKER_BYTES);
    assert_volume_bytes(store, ROOT_MARKER, ROOT_BYTES);
}
