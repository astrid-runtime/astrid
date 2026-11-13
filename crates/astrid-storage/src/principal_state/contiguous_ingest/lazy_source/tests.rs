//! Real owned-file lifetime and publication failure checks.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use astrid_core::PrincipalUid;
use astrid_core::dirs::AstridHome;

use super::super::{ContiguousFileIngest, PackedProjectionIngest};
use super::LazyHomeSource;
use crate::content::{BulkIngestPolicy, ContentIngest, ContentName};
use crate::engine::PrincipalProjectionEngine;
use crate::{KvQuotaResolver, StateOwner, StorageError, open_runtime_principal_store};

#[test]
fn lazy_packed_source_opens_only_on_first_nonempty_read() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("not-created-yet");
    let mut source = LazyHomeSource::new(path.clone(), 3);
    assert_eq!(source.read(&mut []).unwrap(), 0);
    assert!(matches!(source, LazyHomeSource::Pending { .. }));
    std::fs::write(&path, b"abc").unwrap();
    let mut bytes = [0; 3];
    assert_eq!(source.read(&mut bytes).unwrap(), 3);
    assert_eq!(&bytes, b"abc");
    assert!(matches!(source, LazyHomeSource::Reading(_)));
}

#[test]
fn lazy_packed_source_releases_at_eof_and_never_reopens() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("source");
    std::fs::write(&path, b"abc").unwrap();
    let mut source = LazyHomeSource::new(path.clone(), 3);
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes).unwrap();
    assert_eq!(&bytes, b"abc");
    assert!(matches!(source, LazyHomeSource::Complete));
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"a different generation").unwrap();
    assert_eq!(source.read(&mut [0; 32]).unwrap(), 0);
    assert!(matches!(source, LazyHomeSource::Complete));
}

#[derive(Default)]
struct OpenSources {
    current: AtomicUsize,
    peak: AtomicUsize,
}

struct ObservedSource {
    source: LazyHomeSource,
    gauge: Arc<OpenSources>,
    counted: bool,
}

impl Read for ObservedSource {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let result = self.source.read(bytes);
        let open = matches!(self.source, LazyHomeSource::Reading(_));
        if open && !self.counted {
            let current = self
                .gauge
                .current
                .fetch_add(1, Ordering::SeqCst)
                .strict_add(1);
            self.gauge.peak.fetch_max(current, Ordering::SeqCst);
        } else if !open && self.counted {
            self.gauge.current.fetch_sub(1, Ordering::SeqCst);
        }
        self.counted = open;
        result
    }
}

impl Drop for ObservedSource {
    fn drop(&mut self) {
        self.source = LazyHomeSource::Complete;
        if self.counted {
            self.gauge.current.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn owner() -> StateOwner {
    StateOwner::Principal(PrincipalUid::from_bytes([0x64; 32]))
}

fn name(value: &str) -> ContentName {
    ContentName::new(value).unwrap()
}

#[tokio::test]
async fn lazy_packed_sources_bound_open_handles_to_active_content_workers() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let sources = directory.path().join("sources");
    std::fs::create_dir(&sources).unwrap();
    let gauge = Arc::new(OpenSources::default());
    let mut ingests = Vec::new();
    for index in 0..128 {
        let path = sources.join(format!("{index:04}"));
        std::fs::write(&path, b"source bytes").unwrap();
        ingests.push(ContentIngest::new(
            name(&format!("sources/{index:04}")),
            ObservedSource {
                source: LazyHomeSource::new(path, 12),
                gauge: Arc::clone(&gauge),
                counted: false,
            },
        ));
    }
    assert_eq!(gauge.current.load(Ordering::SeqCst), 0);
    store
        .content()
        .put_streaming_batch(&owner(), ingests)
        .unwrap();
    let peak = gauge.peak.load(Ordering::SeqCst);
    assert!(
        peak > 0,
        "the production content pipeline must read real files"
    );
    assert!(peak <= BulkIngestPolicy::default().worker_threads().get());
    assert_eq!(gauge.current.load(Ordering::SeqCst), 0);
    eprintln!("lazy packed source peak open handles: {peak} across 128 sources");
}

#[tokio::test]
async fn lazy_packed_source_open_and_length_failures_publish_no_catalog_changes() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let valid_path = directory.path().join("valid");
    std::fs::write(&valid_path, b"new").unwrap();
    let short_path = directory.path().join("short");
    std::fs::write(&short_path, b"bad").unwrap();
    let cases = [
        (directory.path().join("missing"), 3, "open home source"),
        (short_path, 4, "changed length"),
    ];
    for (bad_path, expected_bytes, context) in cases {
        let valid = name("a-valid");
        let bad = name("z-bad");
        let obsolete = name("obsolete");
        store.content().put(&owner(), &valid, b"prior").unwrap();
        store.content().put(&owner(), &obsolete, b"keep").unwrap();
        let before = store.engine.current_root(&owner()).unwrap();
        let error = store
            .replace_contiguous_files_with_expectation(
                owner(),
                [
                    PackedProjectionIngest::File(ContiguousFileIngest::new(
                        valid.clone(),
                        &valid_path,
                        3,
                    )),
                    PackedProjectionIngest::File(ContiguousFileIngest::new(
                        bad.clone(),
                        &bad_path,
                        expected_bytes,
                    )),
                ],
                std::slice::from_ref(&obsolete),
                None,
                None,
            )
            .expect_err("a late source failure must not publish the earlier source or removal");
        assert!(matches!(&error, StorageError::Internal(_)), "{error}");
        assert!(error.to_string().contains(context), "{error}");
        assert!(
            error.to_string().contains(&bad_path.display().to_string()),
            "{error}"
        );
        assert_eq!(store.engine.current_root(&owner()).unwrap(), before);
        assert_eq!(
            store.content().read(&owner(), &valid).unwrap(),
            Some(b"prior".to_vec())
        );
        assert_eq!(
            store.content().read(&owner(), &obsolete).unwrap(),
            Some(b"keep".to_vec())
        );
        assert_eq!(store.content().read(&owner(), &bad).unwrap(), None);
    }
}

#[tokio::test]
async fn public_contiguous_ingest_keeps_connection_error_variant() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let path = directory.path().join("missing");
    let error = store
        .put_contiguous_files(
            owner(),
            [ContiguousFileIngest::new(name("missing"), &path, 3)],
        )
        .unwrap_err();
    assert!(matches!(&error, StorageError::Connection(_)), "{error}");
    assert!(error.to_string().contains("open home source"), "{error}");
}
