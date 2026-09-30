//! Bounded diagnostic: commit amplification, not a throughput benchmark.

use astrid_storage::volume::{AstridVolume, HostedFileVolume, VolumeRegion};

#[test]
#[ignore = "bounded diagnostic; run explicitly with --ignored --nocapture"]
fn measure_tiny_overwrite_commit_amplification() {
    for extent_count in [128_u64, 4096] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("astrid.volume");
        let region = VolumeRegion::new("objects").unwrap();
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        for offset in 0..extent_count {
            volume.write_region_at(&region, offset, &[42]).unwrap();
        }
        volume.sync().unwrap();
        let baseline = std::fs::metadata(&path).unwrap().len();
        for _ in 0..32 {
            volume.sync().unwrap();
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), baseline);
        for value in 0_u8..32 {
            volume.write_region_at(&region, 0, &[value]).unwrap();
            volume.sync().unwrap();
            assert!(std::fs::metadata(&path).unwrap().len() < 16 * 1024 * 1024);
        }
        let after = std::fs::metadata(&path).unwrap().len();
        assert_eq!(volume.region_len(&region).unwrap(), extent_count);
        drop(volume);
        let volume = HostedFileVolume::open(&path).unwrap();
        let mut recovered = vec![0; usize::try_from(extent_count).unwrap()];
        volume.read_region_at(&region, 0, &mut recovered).unwrap();
        assert_eq!(recovered[0], 31);
        assert!(recovered[1..].iter().all(|byte| *byte == 42));
        volume.reclaim().unwrap();
        let reclaimed = std::fs::metadata(&path).unwrap().len();
        drop(volume);
        let volume = HostedFileVolume::open(&path).unwrap();
        let mut after_reclaim = vec![0; recovered.len()];
        volume
            .read_region_at(&region, 0, &mut after_reclaim)
            .unwrap();
        assert_eq!(after_reclaim, recovered);
        eprintln!(
            "extents={extent_count} logical_bytes={extent_count} baseline={baseline} \
             tiny_writes=32 growth={} bytes_per_commit={} reclaimed={reclaimed}",
            after - baseline,
            (after - baseline) / 32,
        );
    }
}
