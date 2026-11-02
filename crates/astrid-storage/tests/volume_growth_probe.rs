//! Public-API regression: a dirty overwrite+sync must not rewrite the extent map.
//!
//! This is not a throughput benchmark. It only falsifies checkpoint
//! amplification on tiny overwrites.

use astrid_storage::volume::{AstridVolume, HostedFileVolume, VolumeRegion};

#[test]
#[ignore = "sustained disk-write diagnostic; run explicitly"]
fn sustained_overwrites_cross_checkpoint_boundaries() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let writer = HostedFileVolume::open(&path).unwrap();
    writer.create_region(&region, true).unwrap();
    for offset in 0..4096 {
        writer.write_region_at(&region, offset, &[42]).unwrap();
    }
    writer.sync().unwrap();
    let baseline = std::fs::metadata(&path).unwrap().len();
    let started = std::time::Instant::now();
    for batch in 1_u64..=120 {
        for _ in 0..1000 {
            writer.write_region_at(&region, 0, &[17]).unwrap();
            writer.sync().unwrap();
        }
        let metadata = std::fs::metadata(&path).unwrap();
        let growth = metadata.len() - baseline;
        // Stop a regressed implementation before it consumes the host disk.
        assert!(
            growth < batch * 1000 * 512,
            "amplified growth: {growth} after {} commits",
            batch * 1000
        );
        if batch % 20 == 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                eprintln!(
                    "commits={} elapsed_ms={} logical_bytes=4096 file_bytes={} allocated_bytes={} growth={growth}",
                    batch * 1000,
                    started.elapsed().as_millis(),
                    metadata.len(),
                    metadata.blocks() * 512
                );
            }
            let copy = temporary.path().join(format!("recovery-{batch}.volume"));
            std::fs::copy(&path, &copy).unwrap();
            let recovered = HostedFileVolume::open(&copy).unwrap();
            let mut bytes = vec![0; 4096];
            recovered.read_region_at(&region, 0, &mut bytes).unwrap();
            assert_eq!(bytes[0], 17);
            assert!(bytes[1..].iter().all(|value| *value == 42));
        }
    }
    let before_idle = std::fs::metadata(&path).unwrap().len();
    for _ in 0..1000 {
        writer.sync().unwrap();
    }
    assert_eq!(std::fs::metadata(&path).unwrap().len(), before_idle);
}

#[test]
fn tiny_overwrite_commits_do_not_rewrite_the_extent_map() {
    for extent_count in [128_u64, 4096] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("astrid.volume");
        let region = VolumeRegion::new("objects").unwrap();
        let writer = HostedFileVolume::open(&path).unwrap();
        writer.create_region(&region, true).unwrap();
        for offset in 0..extent_count {
            writer.write_region_at(&region, offset, &[42]).unwrap();
        }
        writer.sync().unwrap();
        let baseline = std::fs::metadata(&path).unwrap().len();

        for _ in 0..32 {
            writer.sync().unwrap();
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            baseline,
            "clean sync grew the container"
        );

        for value in 0_u8..32 {
            writer.write_region_at(&region, 0, &[value]).unwrap();
            writer.sync().unwrap();
        }
        let after = std::fs::metadata(&path).unwrap().len();
        let growth = after.checked_sub(baseline).unwrap();
        let bytes_per_commit = growth / 32;
        eprintln!(
            "extents={extent_count} logical_bytes={extent_count} baseline={baseline} \
             tiny_writes=32 growth={growth} bytes_per_commit={bytes_per_commit}"
        );
        assert!(
            bytes_per_commit < 512,
            "extents={extent_count} bytes_per_commit={bytes_per_commit}: dirty commit rewrote the extent map"
        );
        assert_eq!(writer.region_len(&region).unwrap(), extent_count);

        // Copy persisted bytes after the acknowledged dirty syncs, then recover
        // that copy before Drop can flush the writer again.
        let copy = temporary.path().join("after-dirty.volume");
        std::fs::copy(&path, &copy).unwrap();
        let recovered = HostedFileVolume::open(&copy).unwrap();
        let mut recovered_bytes = vec![0; usize::try_from(extent_count).unwrap()];
        recovered
            .read_region_at(&region, 0, &mut recovered_bytes)
            .unwrap();
        assert_eq!(recovered_bytes[0], 31);
        assert!(recovered_bytes[1..].iter().all(|byte| *byte == 42));
        recovered.reclaim().unwrap();
        let reclaimed = std::fs::metadata(&copy).unwrap().len();
        let reclaimed_copy = temporary.path().join("after-reclaim.volume");
        std::fs::copy(&copy, &reclaimed_copy).unwrap();
        drop(recovered);
        let after_reclaim = HostedFileVolume::open(&reclaimed_copy).unwrap();
        let mut actual = vec![0; recovered_bytes.len()];
        after_reclaim
            .read_region_at(&region, 0, &mut actual)
            .unwrap();
        assert_eq!(actual, recovered_bytes);
        eprintln!("extents={extent_count} reclaimed={reclaimed}");
        drop(after_reclaim);
        drop(writer);
    }
}

#[test]
#[ignore = "controlled public-API extent-capacity replay; run explicitly"]
fn one_region_recovers_beyond_the_legacy_snapshot_capacity() {
    assert_fragmented_capacity_recovers(1);
}

#[test]
#[ignore = "controlled public-API extent-capacity replay; run explicitly"]
fn interleaved_regions_recover_beyond_the_legacy_snapshot_capacity() {
    assert_fragmented_capacity_recovers(7);
}

fn assert_fragmented_capacity_recovers(region_count: usize) {
    // ASTMAP1 uses 24 bytes per extent and has a 16 MiB payload ceiling.
    // Cross that real format boundary through ordinary public writes, rather
    // than constructing an impossible namespace or lowering a test-only cap.
    const LEGACY_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
    const LEGACY_EXTENT_BYTES: u64 = 24;
    let extent_count = LEGACY_SNAPSHOT_BYTES / LEGACY_EXTENT_BYTES + 1;
    let region_count_u64 = u64::try_from(region_count).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let writer = HostedFileVolume::open(&path).unwrap();
    let regions: Vec<_> = (0..region_count)
        .map(|index| VolumeRegion::new(format!("region-{index}")).unwrap())
        .collect();
    for region in &regions {
        writer.create_region(region, true).unwrap();
    }
    #[cfg(unix)]
    let original_inode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&path).unwrap().ino()
    };
    for index in 0..extent_count {
        let region = &regions[usize::try_from(index.strict_rem(region_count_u64)).unwrap()];
        let value = u8::try_from(index % 251).unwrap();
        writer
            .write_region_at(region, index.strict_div(region_count_u64), &[value])
            .unwrap();
        if index == extent_count / 2 {
            writer.sync().unwrap();
        }
    }
    // The writes after the earlier acknowledged checkpoint exceed the tail
    // budget. Old code must now describe the enlarged map and fails here.
    writer.sync().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), original_inode);
    }
    let acknowledged_bytes = std::fs::metadata(&path).unwrap().len();
    writer.sync().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), acknowledged_bytes);

    // Recover acknowledged persisted bytes before Drop gets another chance
    // to flush, and verify every mapped byte across all region boundaries.
    let copy = temporary.path().join("acknowledged.volume");
    std::fs::copy(&path, &copy).unwrap();
    let recovered = HostedFileVolume::open(&copy).unwrap();
    for (index, region) in regions.iter().enumerate() {
        let region_index = u64::try_from(index).unwrap();
        let expected_len = extent_count
            .strict_sub(1)
            .strict_sub(region_index)
            .strict_div(region_count_u64)
            .strict_add(1);
        assert_eq!(recovered.region_len(region).unwrap(), expected_len);
        let mut bytes = vec![0; usize::try_from(expected_len).unwrap()];
        recovered.read_region_at(region, 0, &mut bytes).unwrap();
        assert!(bytes.iter().enumerate().all(|(offset, actual)| {
            let global = u64::try_from(offset)
                .unwrap()
                .strict_mul(region_count_u64)
                .strict_add(region_index);
            *actual == u8::try_from(global % 251).unwrap()
        }));
    }
}
