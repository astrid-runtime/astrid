//! Recovery must decode one placement snapshot for both arena safeguards.

use crate::engine::durable::tests::{
    TestEngine, TestIdentity, Utf8Codec, limits, open, transaction,
};
use crate::engine::durable::{DurableEnginePolicy, representations};
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

fn assert_single_placement_snapshot(hosted: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mount = || {
        if hosted {
            TestEngine::open_volume(
                HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap()
                    as Arc<dyn AstridVolume>,
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
    let engine = mount();
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"physical specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    let (commit, transaction) = transaction("alice", None, b"retained state");
    let root = engine.commit(transaction).unwrap().root();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);

    // Repeat with a clean persisted index as well as the first reopen.
    for _ in 0..2 {
        let (reopened, extractions) = representations::count_extractions_during(mount);
        assert_eq!(
            extractions, 1,
            "one placement walk must serve both recovery checks"
        );
        assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(root));
        assert!(reopened.object(commit).unwrap().is_some());
        reopened.close().unwrap();
    }
}

#[test]
fn native_recovery_decodes_generation_zero_placements_once() {
    assert_single_placement_snapshot(false);
}

#[test]
fn volume_recovery_decodes_generation_zero_placements_once() {
    assert_single_placement_snapshot(true);
}
