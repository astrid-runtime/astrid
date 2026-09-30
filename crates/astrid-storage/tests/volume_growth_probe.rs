//! Public-API regression: a dirty overwrite+sync must not rewrite the extent map.
//!
//! This is not a throughput benchmark. It only falsifies checkpoint
//! amplification on tiny overwrites.

use astrid_storage::volume::{AstridVolume, HostedFileVolume, VolumeRegion};

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
