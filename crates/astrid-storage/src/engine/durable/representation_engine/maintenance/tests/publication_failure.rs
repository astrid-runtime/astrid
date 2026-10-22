//! Ambiguous checkpoint publication must force recovery before another use.

use super::*;
use crate::volume::{VolumeMetadataMutation, VolumeRegion};
use std::io::{self, Read};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug)]
struct FailingPublication {
    inner: Arc<dyn AstridVolume>,
    // 1 fails after pointer replacement; 2 arms the following sync failure.
    failure: AtomicU8,
}

impl AstridVolume for FailingPublication {
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()> {
        self.inner.create_region(region, create_new)
    }
    fn region_exists(&self, region: &VolumeRegion) -> io::Result<bool> {
        self.inner.region_exists(region)
    }
    fn region_len(&self, region: &VolumeRegion) -> io::Result<u64> {
        self.inner.region_len(region)
    }
    fn read_region_at(
        &self,
        region: &VolumeRegion,
        offset: u64,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        self.inner.read_region_at(region, offset, buffer)
    }
    fn write_region_from(
        &self,
        region: &VolumeRegion,
        offset: u64,
        len: u64,
        reader: &mut dyn Read,
    ) -> io::Result<()> {
        self.inner.write_region_from(region, offset, len, reader)
    }
    fn set_region_len(&self, region: &VolumeRegion, length: u64) -> io::Result<()> {
        self.inner.set_region_len(region, length)
    }
    fn remove_region(&self, region: &VolumeRegion) -> io::Result<()> {
        self.inner.remove_region(region)
    }
    fn rename_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.rename_region(source, destination)
    }
    fn replace_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.replace_region(source, destination)
    }
    fn list_regions(&self, prefix: &str) -> io::Result<Vec<VolumeRegion>> {
        self.inner.list_regions(prefix)
    }
    fn commit_metadata(&self, mutations: &[VolumeMetadataMutation]) -> io::Result<()> {
        self.inner.commit_metadata(mutations)?;
        if mutations.iter().any(|mutation| {
            matches!(mutation,
            VolumeMetadataMutation::Replace { destination, .. }
            if destination.as_str() == "representations/CURRENT")
        }) {
            match self.failure.load(Ordering::SeqCst) {
                1 => {
                    self.failure.store(0, Ordering::SeqCst);
                    return Err(io::Error::other(
                        "injected error after checkpoint replacement",
                    ));
                },
                2 => self.failure.store(3, Ordering::SeqCst),
                _ => {},
            }
        }
        Ok(())
    }
    fn sync(&self) -> io::Result<()> {
        if self
            .failure
            .compare_exchange(3, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(io::Error::other("injected checkpoint durability failure"));
        }
        self.inner.sync()
    }
}

#[test]
fn failed_automatic_checkpoint_requires_recovery_and_preserves_all_objects() {
    for failure in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let media = Arc::new(FailingPublication {
            inner: HostedFileVolume::open(directory.path().join("test.volume")).unwrap(),
            failure: AtomicU8::new(0),
        });
        let engine = DurableEngine::open_volume(
            media.clone(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            DurableEnginePolicy::default(),
        )
        .unwrap();
        specification(&engine);
        media.failure.store(failure, Ordering::SeqCst);
        let mut objects = Vec::new();
        let mut failed = false;
        for ordinal in 0_u64..8192 {
            let record = ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                ordinal.to_le_bytes().to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .unwrap();
            objects.push(engine.identify(&record));
            if engine.persist_standalone_object(&record).is_err() {
                assert!(engine.inner.lock().poisoned);
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "exercise an actual automatic checkpoint publication failure"
        );
        assert_eq!(media.failure.load(Ordering::SeqCst), 0);
        // The public read path must reopen instead of using either stale set
        // of generation handles. All acknowledged objects remain available;
        // the last (unacknowledged) insertion was already durable as well.
        for id in objects {
            assert!(
                engine
                    .object_for(&"alice".to_owned(), id)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(!engine.inner.lock().poisoned);
        engine.close().unwrap();
    }
}
