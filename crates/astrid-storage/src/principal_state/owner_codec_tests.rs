//! Compatibility and fail-closed regressions for the consolidated V2 owner.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    Blake3ObjectIdentityV1, RuntimeEngine, RuntimeStateOwnerCodecV2, StateOwner, StateOwnerCodecV2,
    open_runtime_principal_store,
};
use crate::engine::{
    DurableEngine, DurableEnginePolicy, DurableError, GroupCommitPolicy, ObjectCacheConfig,
    PersistentObjectIdentity, PrincipalCodec, RecoveryLimits, RecoveryRetryPolicy, RootTransaction,
    TransactionWalPolicy, durable::inspect_native_root_history_without_repair,
    durable::inspect_native_wal_owners_without_repair,
};
use crate::kv::KvQuotaResolver;
use crate::storage_model::ObjectIdentity;
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use astrid_core::dirs::AstridHome;
use std::num::NonZeroU64;

fn user_owner() -> StateOwner {
    StateOwner::User(astrid_core::UserUid::from_bytes([11; 32]))
}

fn corrupt_last_byte(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let Some(last) = bytes.len().checked_sub(1) else {
        panic!("cannot corrupt an empty test file");
    };
    bytes[last] ^= 0x80;
    std::fs::write(path, bytes).unwrap();
}

fn append_file(source: &Path, destination: &Path) {
    let bytes = std::fs::read(source).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(destination)
        .unwrap();
    file.write_all(&bytes).unwrap();
}

fn append_bytes(bytes: &[u8], destination: &Path) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(destination)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn owner_scan_finds_user_after_malformed_root_frame() {
    let principal_source = tempfile::tempdir().unwrap();
    let principal = DurableEngine::open(
        principal_source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    principal
        .commit(RootTransaction::new(
            StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([7; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    principal.close().unwrap();

    let user_source = tempfile::tempdir().unwrap();
    let user = DurableEngine::open(
        user_source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    user.commit(RootTransaction::new(
        user_owner(),
        None,
        commit_id,
        vec![(commit_id, commit)],
    ))
    .unwrap();
    user.close().unwrap();

    let candidate = tempfile::tempdir().unwrap();
    std::fs::copy(
        principal_source.path().join("roots.journal"),
        candidate.path().join("roots.journal"),
    )
    .unwrap();
    corrupt_last_byte(&candidate.path().join("roots.journal"));
    append_file(
        &user_source.path().join("roots.journal"),
        &candidate.path().join("roots.journal"),
    );
    let before = std::fs::read(candidate.path().join("roots.journal")).unwrap();

    let observations = inspect_native_root_history_without_repair::<StateOwner, _>(
        &candidate.path().join("roots.journal"),
        Blake3ObjectIdentityV1.scheme(),
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert!(observations.owners.contains(&user_owner()));
    assert!(observations.scan_error.is_some());
    assert_eq!(
        std::fs::read(candidate.path().join("roots.journal")).unwrap(),
        before
    );
}

#[test]
fn root_semantic_malformed_only_fails_closed_without_user() {
    let source = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open(
        source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([12; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    engine.close().unwrap();

    let path = source.path().join("roots.journal");
    corrupt_last_byte(&path);
    let before = std::fs::read(&path).unwrap();
    let observations = inspect_native_root_history_without_repair::<StateOwner, _>(
        &path,
        Blake3ObjectIdentityV1.scheme(),
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert!(observations.owners.is_empty());
    assert!(observations.scan_error.is_some());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn root_user_wins_when_malformed_evidence_follows() {
    let source = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open(
        source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    engine.close().unwrap();

    let malformed_source = tempfile::tempdir().unwrap();
    let malformed = DurableEngine::open(
        malformed_source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    malformed
        .commit(RootTransaction::new(
            StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([13; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    malformed.close().unwrap();

    let path = source.path().join("roots.journal");
    append_file(&malformed_source.path().join("roots.journal"), &path);
    corrupt_last_byte(&path);
    let before = std::fs::read(&path).unwrap();
    let observations = inspect_native_root_history_without_repair::<StateOwner, _>(
        &path,
        Blake3ObjectIdentityV1.scheme(),
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert!(observations.owners.contains(&user_owner()));
    assert!(observations.scan_error.is_some());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn owner_scan_handles_ordinary_multiframe_root_journal() {
    let source = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open(
        source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let owner = StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([9; 32]));
    let mut expected = None;
    for index in 0..256u64 {
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::new(3).unwrap(),
            format!("ordinary multiframe root {index}").into_bytes(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = Blake3ObjectIdentityV1.identify(&commit);
        expected = Some(
            engine
                .commit(RootTransaction::new(
                    owner,
                    expected,
                    commit_id,
                    vec![(commit_id, commit)],
                ))
                .unwrap()
                .root(),
        );
    }
    engine.close().unwrap();

    let started = std::time::Instant::now();
    let observations = inspect_native_root_history_without_repair::<StateOwner, _>(
        &source.path().join("roots.journal"),
        Blake3ObjectIdentityV1.scheme(),
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert!(observations.owners.contains(&owner));
    assert!(observations.scan_error.is_none());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "ordinary multiframe root scan took {:?}",
        started.elapsed()
    );
}

#[test]
fn owner_scan_finds_user_after_malformed_wal_frame() {
    let policy = || {
        DurableEnginePolicy::new(
            GroupCommitPolicy::immediate(),
            RecoveryRetryPolicy::immediate(),
            ObjectCacheConfig::<StateOwner>::disabled(),
        )
        .with_transaction_wal(TransactionWalPolicy::enabled(
            NonZeroU64::new(u64::MAX).unwrap(),
        ))
    };
    let principal_source = tempfile::tempdir().unwrap();
    let principal = DurableEngine::open_with_policy(
        principal_source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    principal
        .commit(RootTransaction::new(
            StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([8; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    drop(principal);

    let user_source = tempfile::tempdir().unwrap();
    let user = DurableEngine::open_with_policy(
        user_source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy(),
    )
    .unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    user.commit(RootTransaction::new(
        user_owner(),
        None,
        commit_id,
        vec![(commit_id, commit)],
    ))
    .unwrap();
    drop(user);

    let candidate = tempfile::tempdir().unwrap();
    std::fs::copy(
        principal_source.path().join("transactions.wal"),
        candidate.path().join("transactions.wal"),
    )
    .unwrap();
    corrupt_last_byte(&candidate.path().join("transactions.wal"));
    let principal_wal = std::fs::read(principal_source.path().join("transactions.wal")).unwrap();
    while std::fs::metadata(candidate.path().join("transactions.wal"))
        .unwrap()
        .len()
        < 128 * 1024
    {
        append_bytes(&principal_wal, &candidate.path().join("transactions.wal"));
    }
    assert!(
        std::fs::metadata(candidate.path().join("transactions.wal"))
            .unwrap()
            .len()
            <= 1024 * 1024,
        "realistic WAL fixture must remain bounded"
    );
    append_file(
        &user_source.path().join("transactions.wal"),
        &candidate.path().join("transactions.wal"),
    );
    let before = std::fs::read(candidate.path().join("transactions.wal")).unwrap();
    assert!(
        before.len() >= 128 * 1024,
        "realistic WAL size: {}",
        before.len()
    );

    let started = std::time::Instant::now();

    let observations = inspect_native_wal_owners_without_repair::<StateOwner, _>(
        &candidate.path().join("transactions.wal"),
        Blake3ObjectIdentityV1,
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert!(observations.owners.contains(&user_owner()));
    assert!(observations.scan_error.is_some());
    assert_eq!(
        std::fs::read(candidate.path().join("transactions.wal")).unwrap(),
        before
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "bounded WAL resynchronization took {:?}",
        started.elapsed()
    );
}

fn user_bytes() -> Vec<u8> {
    let mut bytes = vec![3];
    bytes.extend_from_slice(&[11; 32]);
    bytes
}

fn commit_record() -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::new(3).unwrap(),
        Vec::new(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn file_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn tree_bytes(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in walk(path) {
        if entry.is_file() {
            files.insert(entry.clone(), std::fs::read(entry).unwrap());
        }
    }
    files
}

fn walk(path: &Path) -> Vec<std::path::PathBuf> {
    let mut entries = Vec::new();
    let Ok(read) = std::fs::read_dir(path) else {
        return entries;
    };
    for entry in read.map(Result::unwrap) {
        let path = entry.path();
        if path.is_dir() {
            entries.extend(walk(&path));
        } else {
            entries.push(path);
        }
    }
    entries
}

#[test]
fn pure_v2_round_trips_all_four_canonical_tags() {
    let codec = StateOwnerCodecV2;
    let owners = [
        StateOwner::System,
        StateOwner::Principal(astrid_core::identity::PrincipalUid::from_bytes([7; 32])),
        StateOwner::Fleet(astrid_core::FleetUid::from_bytes([8; 32])),
        user_owner(),
    ];
    let mut principal_bytes = vec![1];
    principal_bytes.extend_from_slice(&[7; 32]);
    let mut fleet_bytes = vec![2];
    fleet_bytes.extend_from_slice(&[8; 32]);
    let expected = [vec![0], principal_bytes, fleet_bytes, user_bytes()];
    for (owner, bytes) in owners.iter().zip(expected) {
        let encoded = codec.encode(owner);
        assert_eq!(encoded, bytes);
        assert_eq!(codec.decode(&encoded).as_ref(), Some(owner));
    }

    for malformed in [
        &[][..],
        &[0, 0][..],
        &[1][..],
        &[1, 7][..],
        &[2][..],
        &[2, 8][..],
        &[3][..],
        &[3, 11][..],
        &[4][..],
        &[0xff][..],
    ] {
        assert_eq!(codec.decode(malformed), None, "{malformed:?}");
    }
}

#[test]
fn runtime_v2_delegates_admitted_tags_and_refuses_user() {
    let codec = RuntimeStateOwnerCodecV2;
    let mut principal_bytes = vec![1];
    principal_bytes.extend_from_slice(&[7; 32]);
    assert_eq!(codec.encode(&StateOwner::System), [0]);
    assert_eq!(
        codec.decode(&principal_bytes),
        Some(StateOwner::Principal(
            astrid_core::identity::PrincipalUid::from_bytes([7; 32])
        ))
    );
    assert!(codec.encode(&user_owner()).is_empty());
    assert_eq!(codec.decode(&user_bytes()), None);
    assert!(matches!(
        codec.admit_principal(&user_owner()),
        Err(DurableError::UnsupportedPrincipal)
    ));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn independent_python_reader_agrees_with_v2_owner_grammar() {
    let script_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let path = script_directory
        .join("runatal_v1_reader.py")
        .canonicalize()
        .unwrap();
    let directory = script_directory.canonicalize().unwrap();
    let path_display = path.display();
    let directory_display = directory.display();
    let code = format!(
        r#"import importlib.util
import sys
sys.path.insert(0, r"{directory_display}")
path = r"{path_display}"
spec = importlib.util.spec_from_file_location("runatal_reader", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.principal_text(b"\0") == "system"
for tag, prefix in ((1, ""), (2, "fleet:"), (3, "user:")):
    assert module.principal_text(bytes([tag]) + bytes(32)) == prefix + "00" * 32
for malformed in (b"", b"\0\0", bytes([1]) + bytes(31), bytes([3]) + bytes(31)):
    try:
        module.principal_text(malformed)
    except module.FormatError:
        pass
    else:
        raise AssertionError("malformed owner accepted")
"#
    );
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(code)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn direct_runtime_commit_rejects_user_before_durable_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let engine = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let before = tree_bytes(directory.path());
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);

    let error = engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit.clone())],
        ))
        .unwrap_err();
    assert!(matches!(error, DurableError::UnsupportedPrincipal));
    assert_eq!(engine.root(&user_owner()).unwrap(), None);
    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(tree_bytes(directory.path()), before);
}

#[tokio::test]
async fn runtime_store_and_staging_reject_user_before_home_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let before = tree_bytes(directory.path());
    let name = crate::ContentName::new("user.bin").unwrap();

    let error = store
        .staging()
        .begin(user_owner(), name, crate::ChunkingProfile::ASTRID_V1)
        .unwrap_err();
    assert!(error.to_string().contains("user StateOwner"));
    assert!(store.staging().ready().unwrap().is_empty());
    assert_eq!(tree_bytes(directory.path()), before);
}

#[tokio::test]
async fn runtime_quota_rejects_user_without_invoking_underlying_resolver() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let underlying_invoked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&underlying_invoked);
    let store = open_runtime_principal_store(
        &home,
        Arc::new(move |_: &StateOwner| {
            flag.store(true, Ordering::SeqCst);
            Ok(None)
        }),
    )
    .await
    .unwrap();
    let name = crate::ContentName::new("user.bin").unwrap();

    let error = store
        .content()
        .put(&user_owner(), &name, b"throwaway")
        .unwrap_err();
    assert!(error.to_string().contains("user StateOwner"));
    assert!(!underlying_invoked.load(Ordering::SeqCst));
    assert_eq!(store.engine.root(&user_owner()).unwrap(), None);
}

#[test]
fn forged_tag3_root_recovery_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    let pure_engine = DurableEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    pure_engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit.clone())],
        ))
        .unwrap();
    pure_engine.close().unwrap();

    let error = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap_err();
    assert!(matches!(error, DurableError::InvalidPrincipal { .. }));
}

#[test]
fn forged_tag3_snapshot_recovery_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    let pure_engine = DurableEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    pure_engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit.clone())],
        ))
        .unwrap();
    let replacement = directory.path().join("replacement.journal");
    pure_engine
        .write_mapped_root_snapshot(&replacement, &StateOwnerCodecV2, |owner| {
            debug_assert!(matches!(owner, StateOwner::User(_)));
            Ok(*owner)
        })
        .unwrap();
    pure_engine.close().unwrap();
    std::fs::rename(&replacement, directory.path().join("roots.journal")).unwrap();

    let error = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap_err();
    assert!(matches!(error, DurableError::InvalidPrincipal { .. }));
}

#[test]
fn forged_tag3_transaction_wal_recovery_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::<StateOwner>::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(u64::MAX).unwrap(),
    ));
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    let pure_engine = DurableEngine::open_with_policy(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .unwrap();
    pure_engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit.clone())],
        ))
        .unwrap();
    drop(pure_engine);

    let roots = directory.path().join("roots.journal");
    std::fs::File::create(&roots).unwrap();
    let wal_before = file_bytes(&directory.path().join("transactions.wal"));
    assert!(
        wal_before
            .windows(user_bytes().len())
            .any(|bytes| bytes == user_bytes())
    );
    let arena_before = file_bytes(&directory.path().join("objects.arena"));

    let error = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DurableError::Corrupt {
            detail: "WAL principal encoding is not canonical",
            ..
        }
    ));
    assert_eq!(
        file_bytes(&directory.path().join("transactions.wal")),
        wal_before
    );
    assert_eq!(
        file_bytes(&directory.path().join("objects.arena")),
        arena_before
    );
    assert_eq!(std::fs::read(&roots).unwrap(), Vec::<u8>::new());
}

#[test]
fn forged_tag3_wal_with_missing_object_preserves_recovery_inputs() {
    let source = tempfile::tempdir().unwrap();
    let policy = || {
        DurableEnginePolicy::new(
            GroupCommitPolicy::immediate(),
            RecoveryRetryPolicy::immediate(),
            ObjectCacheConfig::<StateOwner>::disabled(),
        )
        .with_transaction_wal(TransactionWalPolicy::enabled(
            NonZeroU64::new(u64::MAX).unwrap(),
        ))
    };
    let commit = commit_record();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    let source_engine = DurableEngine::open_with_policy(
        source.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy(),
    )
    .unwrap();
    source_engine
        .commit(RootTransaction::new(
            user_owner(),
            None,
            commit_id,
            vec![(commit_id, commit.clone())],
        ))
        .unwrap();
    drop(source_engine);

    let empty = tempfile::tempdir().unwrap();
    let empty_engine = DurableEngine::open_with_policy(
        empty.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy(),
    )
    .unwrap();
    empty_engine.close().unwrap();

    let candidate = tempfile::tempdir().unwrap();
    for name in ["objects.arena", "objects.index", "roots.journal"] {
        std::fs::copy(empty.path().join(name), candidate.path().join(name)).unwrap();
    }
    std::fs::copy(
        source.path().join("transactions.wal"),
        candidate.path().join("transactions.wal"),
    )
    .unwrap();

    let inputs = [
        "objects.arena",
        "objects.index",
        "roots.journal",
        "transactions.wal",
    ]
    .map(|name| (name, file_bytes(&candidate.path().join(name))));
    assert!(inputs.iter().any(|(_, bytes)| {
        bytes
            .windows(user_bytes().len())
            .any(|window| window == user_bytes())
    }));

    let error = RuntimeEngine::open(
        candidate.path(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DurableError::Corrupt {
            detail: "WAL principal encoding is not canonical",
            ..
        }
    ));
    for (name, bytes) in inputs {
        assert_eq!(file_bytes(&candidate.path().join(name)), bytes, "{name}");
    }
}
