//! Namespace transactions move region ownership without cloning extent maps.

use super::test_support::read_container;
use super::*;

fn region(name: &str) -> VolumeRegion {
    VolumeRegion::new(name).unwrap()
}

fn fixture() -> (tempfile::TempDir, Arc<HostedFileVolume>) {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    for (name, bytes) in [
        ("current", b"old".as_slice()),
        ("prepared", b"new".as_slice()),
    ] {
        let name = region(name);
        volume.create_region(&name, true).unwrap();
        volume.write_region_at(&name, 0, bytes).unwrap();
    }
    volume.sync().unwrap();
    (directory, volume)
}

fn read(volume: &HostedFileVolume, name: &str) -> Vec<u8> {
    let name = region(name);
    let mut bytes = vec![0; usize::try_from(volume.region_len(&name).unwrap()).unwrap()];
    assert_eq!(
        volume.read_region_at(&name, 0, &mut bytes).unwrap(),
        bytes.len()
    );
    bytes
}

fn replacement() -> VolumeMetadataMutation {
    VolumeMetadataMutation::Replace {
        source: region("prepared"),
        destination: region("current"),
    }
}

#[test]
fn metadata_transaction_moves_regions_without_cloning_extent_maps() {
    let (directory, volume) = fixture();
    let unrelated = region("unrelated");
    volume.create_region(&unrelated, true).unwrap();
    for offset in 0_u8..128 {
        volume
            .write_region_at(&unrelated, u64::from(offset), &[offset])
            .unwrap();
    }
    volume.sync().unwrap();
    REGION_STATE_CLONES.with(|count| count.set(0));
    volume.commit_metadata(&[replacement()]).unwrap();
    assert_eq!(
        REGION_STATE_CLONES.with(Cell::get),
        0,
        "namespace publication must not clone region extents"
    );
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    assert_eq!(read(&reopened, "current"), b"new");
    assert!(!reopened.region_exists(&region("prepared")).unwrap());
    assert_eq!(
        read(&reopened, "unrelated"),
        (0_u8..128).collect::<Vec<_>>()
    );
}

#[test]
fn metadata_transaction_preserves_chained_names_and_self_replace() {
    let (directory, volume) = fixture();
    volume
        .commit_metadata(&[
            VolumeMetadataMutation::Rename {
                source: region("current"),
                destination: region("temporary"),
            },
            VolumeMetadataMutation::Rename {
                source: region("prepared"),
                destination: region("current"),
            },
            VolumeMetadataMutation::Replace {
                source: region("temporary"),
                destination: region("current"),
            },
            VolumeMetadataMutation::Replace {
                source: region("current"),
                destination: region("current"),
            },
        ])
        .unwrap();
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    assert_eq!(read(&reopened, "current"), b"old");
    assert!(!reopened.region_exists(&region("prepared")).unwrap());
    assert!(!reopened.region_exists(&region("temporary")).unwrap());
}

#[test]
fn invalid_late_metadata_mutation_leaves_media_and_namespace_unchanged() {
    let (_directory, volume) = fixture();
    let before = read_container(&volume);
    let error = volume
        .commit_metadata(&[
            VolumeMetadataMutation::Rename {
                source: region("prepared"),
                destination: region("temporary"),
            },
            VolumeMetadataMutation::Replace {
                source: region("absent"),
                destination: region("current"),
            },
        ])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(read_container(&volume), before);
    assert_eq!(read(&volume, "current"), b"old");
    assert_eq!(read(&volume, "prepared"), b"new");
    assert!(!volume.region_exists(&region("temporary")).unwrap());
    assert!(
        volume
            .commit_metadata(&[VolumeMetadataMutation::Rename {
                source: region("current"),
                destination: region("current"),
            }])
            .is_err()
    );
    assert_eq!(read_container(&volume), before);
}

#[test]
fn failed_metadata_append_preserves_namespace_then_retries_and_recovers() {
    for successful_writes in [0, 3, 8, 9] {
        let (directory, volume) = fixture();
        let before = {
            let state = volume.state.lock();
            (state.valid_len, state.sequence)
        };
        assert!(
            HostedFileVolume::with_append_failure_for_test(successful_writes, || {
                volume.commit_metadata(&[replacement()])
            })
            .is_err()
        );
        assert_eq!(read(&volume, "current"), b"old");
        assert_eq!(read(&volume, "prepared"), b"new");
        {
            let state = volume.state.lock();
            assert_eq!((state.valid_len, state.sequence), before);
        }
        volume.commit_metadata(&[replacement()]).unwrap();
        volume.sync().unwrap();
        drop(volume);
        let reopened = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
        assert_eq!(read(&reopened, "current"), b"new");
        assert!(!reopened.region_exists(&region("prepared")).unwrap());
    }
}

#[test]
fn metadata_preflight_matches_full_namespace_for_all_two_step_transitions() {
    let names = [region("a"), region("b"), region("c")];
    let mut operations = Vec::new();
    for source in &names {
        for destination in &names {
            operations.push(VolumeMetadataMutation::Rename {
                source: source.clone(),
                destination: destination.clone(),
            });
            operations.push(VolumeMetadataMutation::Replace {
                source: source.clone(),
                destination: destination.clone(),
            });
        }
    }
    for mask in 0_u8..8 {
        let mut initial = BTreeMap::from([(region("unrelated"), 99_u8)]);
        for (index, name) in names.iter().enumerate() {
            if mask & (1 << index) != 0 {
                initial.insert(name.clone(), mask);
            }
        }
        for first in &operations {
            for second in &operations {
                let mutations = [first.clone(), second.clone()];
                let mut full = initial.clone();
                let expected = apply_metadata_mutations(&mut full, &mutations)
                    .map_err(|error| (error.kind(), error.to_string()));
                let projected = preflight_metadata_mutations(&initial, &mutations)
                    .map_err(|error| (error.kind(), error.to_string()));
                assert_eq!(projected, expected, "occupancy {mask}: {mutations:?}");
            }
        }
    }
}
