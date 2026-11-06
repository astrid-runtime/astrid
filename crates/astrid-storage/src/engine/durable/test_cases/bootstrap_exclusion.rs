//! Bootstrap evidence must remain independent after a predecessor reopens it.
use super::*;
use crate::volume::HostedFileVolume;

fn evidence(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        bytes.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

#[test]
fn predecessor_repair_cannot_silently_make_successor_bootstrap_relocatable() {
    for volume_backed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let reopen = || {
            if volume_backed {
                TestEngine::open_volume(
                    HostedFileVolume::open(directory.path().join("test.volume")).unwrap(),
                    TestIdentity,
                    Utf8Codec,
                    limits(),
                    DurableEnginePolicy::default(),
                )
                .unwrap()
            } else {
                open(directory.path())
            }
        };
        let old_specification = evidence(b"old independently recoverable format");
        let new_specification = evidence(b"successor independently recoverable format");
        let engine = reopen();
        let old_id = engine
            .persist_bootstrap_object(&old_specification)
            .unwrap()
            .0;
        let (commit_id, transaction) = transaction("alice", None, b"required historical data");
        let expected_root = engine.commit(transaction).unwrap().root();
        engine
            .ensure_direct_representation_catalogue(old_id, &[old_id])
            .unwrap();
        let new_id = engine
            .persist_bootstrap_object(&new_specification)
            .unwrap()
            .0;
        assert!(
            !engine
                .inner
                .lock()
                .representations
                .as_ref()
                .unwrap()
                .contains_direct(new_id)
        );
        engine.close().unwrap();
        drop(engine);

        // Reproduce the predecessor's real coverage repair with the exclusion
        // list it knows: the successor bootstrap is an ordinary indexed object.
        let predecessor = reopen();
        predecessor
            .ensure_direct_representation_catalogue(old_id, &[old_id])
            .unwrap();
        assert!(
            predecessor
                .inner
                .lock()
                .representations
                .as_ref()
                .unwrap()
                .contains_direct(new_id)
        );
        predecessor.close().unwrap();
        drop(predecessor);

        let successor = reopen();
        let before = successor
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .active();
        let result = successor.ensure_direct_representation_catalogue_compatible_with(
            new_id,
            &[old_id],
            &[old_id, new_id],
        );
        assert!(
            matches!(
                result,
                Err(DurableError::InvalidRepresentationState(
                    "bootstrap object has a relocatable representation"
                ))
            ),
            "volume_backed={volume_backed}: {result:?}"
        );
        assert_eq!(
            successor
                .inner
                .lock()
                .representations
                .as_ref()
                .unwrap()
                .active(),
            before
        );
        assert_eq!(
            successor.root(&"alice".to_owned()).unwrap(),
            Some(expected_root)
        );
        assert!(successor.object(commit_id).unwrap().is_some());
        assert_eq!(successor.object(old_id).unwrap(), Some(old_specification));
        assert_eq!(successor.object(new_id).unwrap(), Some(new_specification));
        successor.close().unwrap();
    }
}
