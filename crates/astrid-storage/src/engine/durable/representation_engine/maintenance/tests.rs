use super::super::super::tests::{TestIdentity, Utf8Codec, transaction};
use super::super::super::{
    DurableEngine, DurableEnginePolicy, ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord,
    RecoveryLimits, TransactionWalPolicy,
};
use crate::volume::{AstridVolume, HostedFileVolume};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;

type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

fn open(path: &Path, volume: bool, wal: bool) -> TestEngine {
    let transaction_wal = if wal {
        TransactionWalPolicy::enabled(NonZeroU64::MIN)
    } else {
        TransactionWalPolicy::disabled()
    };
    let policy = DurableEnginePolicy::default().with_transaction_wal(transaction_wal);
    if volume {
        let media: Arc<dyn AstridVolume> =
            HostedFileVolume::open(path.join("test.volume")).unwrap();
        DurableEngine::open_volume(
            media,
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            policy,
        )
        .unwrap()
    } else {
        DurableEngine::open_with_policy(
            path,
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            policy,
        )
        .unwrap()
    }
}

fn specification(engine: &TestEngine) -> crate::storage_model::ObjectId {
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"physical history checkpoint specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    engine
        .ensure_direct_representation_catalogue(id, &[id])
        .unwrap();
    id
}

fn physical_nodes(engine: &TestEngine) -> usize {
    engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .persisted_physical_node_count()
}

fn generation(path: &Path, volume: bool, engine: &TestEngine) -> u64 {
    let names = if volume {
        engine
            .volume
            .read()
            .as_ref()
            .unwrap()
            .list_regions("representations/generations/")
            .unwrap()
            .into_iter()
            .map(|region| region.as_str().to_owned())
            .collect::<Vec<_>>()
    } else {
        std::fs::read_dir(path.join("representations/generations"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
            .collect()
    };
    names
        .iter()
        .filter_map(|name| {
            let suffix = name
                .strip_prefix("representations/generations/")
                .unwrap_or(name);
            u64::from_str_radix(suffix.split('/').next().unwrap(), 16).ok()
        })
        .max()
        .unwrap()
}

#[test]
fn ordinary_commits_checkpoint_obsolete_physical_ids_without_dropping_history() {
    for volume in [false, true] {
        for wal in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let engine = open(directory.path(), volume, wal);
            let specification = specification(&engine);
            let mut root = None;
            let mut commits = Vec::new();
            let mut previous_nodes = 0;
            let mut observed_reclaim = false;
            for ordinal in 0_u64..16384 {
                let (id, transaction) = transaction("alice", root, &ordinal.to_le_bytes());
                root = Some(engine.commit(transaction).unwrap().root());
                commits.push(id);
                let nodes = physical_nodes(&engine);
                observed_reclaim |= nodes < previous_nodes;
                previous_nodes = nodes;
                if ordinal % 1024 == 1023 {
                    eprintln!("commits volume={volume} wal={wal} count={}", ordinal + 1);
                    if generation(directory.path(), volume, &engine) > 1 {
                        break;
                    }
                }
                let inner = engine.inner.lock();
                assert!(
                    !inner
                        .representations
                        .as_ref()
                        .unwrap()
                        .checkpoint_required()
                );
            }
            engine.flush().unwrap();
            assert!(
                observed_reclaim,
                "automatic checkpoint must actually release IDs"
            );
            assert!(
                generation(directory.path(), volume, &engine) > 1,
                "exercise automatic checkpoint: volume={volume} wal={wal}"
            );
            let active = engine
                .inner
                .lock()
                .representations
                .as_ref()
                .unwrap()
                .active();
            engine.close().unwrap();
            drop(engine);
            let recovered = open(directory.path(), volume, wal);
            assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), root);
            assert_eq!(
                recovered
                    .ensure_direct_representation_catalogue(specification, &[specification])
                    .unwrap(),
                active
            );
            for id in commits {
                assert!(
                    recovered
                        .object_for(&"alice".to_owned(), id)
                        .unwrap()
                        .is_some()
                );
            }
            recovered.close().unwrap();
        }
    }
}

#[test]
fn standalone_publication_also_checkpoints_physical_history() {
    for volume in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path(), volume, false);
        specification(&engine);
        let mut objects = Vec::new();
        let mut previous_nodes = 0;
        let mut observed_reclaim = false;
        for ordinal in 0_u64..16384 {
            let record = ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                ordinal.to_le_bytes().to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .unwrap();
            objects.push(engine.persist_standalone_object(&record).unwrap().0);
            let nodes = physical_nodes(&engine);
            observed_reclaim |= nodes < previous_nodes;
            previous_nodes = nodes;
            if ordinal % 1024 == 1023 {
                eprintln!("standalone volume={volume} count={}", ordinal + 1);
                if generation(directory.path(), volume, &engine) > 1 {
                    break;
                }
            }
            assert!(
                !engine
                    .inner
                    .lock()
                    .representations
                    .as_ref()
                    .unwrap()
                    .checkpoint_required()
            );
        }
        assert!(generation(directory.path(), volume, &engine) > 1);
        assert!(
            observed_reclaim,
            "automatic checkpoint must actually release IDs"
        );
        engine.close().unwrap();
        drop(engine);
        let recovered = open(directory.path(), volume, false);
        for id in objects {
            assert!(
                recovered
                    .object_for(&"alice".to_owned(), id)
                    .unwrap()
                    .is_some()
            );
        }
        recovered.close().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn standalone_volume_insert_is_committed_before_close() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path(), true, false);
    specification(&engine);
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"standalone acknowledgement".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    // Copy before close/Drop can supply a missing container commit boundary.
    // Unix permits this read while holding the volume's advisory inode lock.
    let snapshot = directory.path().join("snapshot.volume");
    std::fs::copy(directory.path().join("test.volume"), &snapshot).unwrap();
    let recovered = DurableEngine::open_volume(
        HostedFileVolume::open(&snapshot).unwrap(),
        TestIdentity,
        Utf8Codec,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    assert_eq!(
        recovered.object_for(&"alice".to_owned(), id).unwrap(),
        Some(record)
    );
    recovered.close().unwrap();
    engine.close().unwrap();
}

mod publication_failure;
