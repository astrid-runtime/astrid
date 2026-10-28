use super::super::representations::DIRECT_ARENA_WALKS;
use super::super::tests::{TestEngine, TestIdentity, Utf8Codec, limits, open};
use super::super::*;
use crate::volume::HostedFileVolume;

fn open_backend(path: &std::path::Path, hosted: bool) -> TestEngine {
    if hosted {
        TestEngine::open_volume(
            HostedFileVolume::open(path.join("test.volume")).unwrap(),
            TestIdentity,
            Utf8Codec,
            limits(),
            DurableEnginePolicy::default(),
        )
        .unwrap()
    } else {
        open(path)
    }
}

#[test]
fn generation_zero_mount_consumes_validated_locations_without_another_map_walk() {
    for hosted in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open_backend(directory.path(), hosted);
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            b"physical-format".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let (object, _) = engine.persist_standalone_object(&record).unwrap();
        engine
            .ensure_direct_representation_catalogue(object, &[object])
            .unwrap();
        drop(engine);
        DIRECT_ARENA_WALKS.with(|count| count.set(0));
        let reopened = open_backend(directory.path(), hosted);
        assert_eq!(reopened.object(object).unwrap(), Some(record));
        DIRECT_ARENA_WALKS.with(|count| {
            assert_eq!(
                count.get(),
                0,
                "mount re-decoded already validated placements (hosted={hosted})"
            );
        });
    }
}
