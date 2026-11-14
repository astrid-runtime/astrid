//! Real-handle coverage for [`super::read::AuthenticatedContentReader`].

use std::io::{self, Read};
use std::sync::Arc;

use parking_lot::RwLock;

use super::read::AuthenticatedContentReader;
use crate::content::{ContentName, PrincipalContentStore};
use crate::engine::{
    CommitOutcome, InMemoryEngine, PrincipalProjectionEngine, PrincipalProjectionError,
    RootTransaction,
};
use crate::storage_model::{InsertOutcome, ObjectId, ObjectRecord, ReferenceKind, RootState};

use crate::principal_state::Blake3ObjectIdentityV1;

type Engine = InMemoryEngine<String, Blake3ObjectIdentityV1>;

struct MissingObjectEngine {
    inner: Engine,
    missing: RwLock<Option<ObjectId>>,
}

impl MissingObjectEngine {
    fn new() -> Self {
        Self {
            inner: Engine::new(Blake3ObjectIdentityV1),
            missing: RwLock::new(None),
        }
    }

    fn hide(&self, object: ObjectId) {
        *self.missing.write() = Some(object);
    }
}

impl PrincipalProjectionEngine<String> for MissingObjectEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.inner.put_object(record).map_err(Into::into)
    }

    fn current_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        if *self.missing.read() == Some(id) {
            return Ok(None);
        }
        Ok(self.inner.object(id))
    }

    fn commit_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.inner.commit(transaction).map_err(Into::into)
    }

    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

fn deterministic_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn put_and_open(
    store: &PrincipalContentStore<String, Engine>,
    name: &str,
    bytes: &[u8],
) -> crate::content::PrincipalContentReadHandle<String, Engine> {
    let owner = "restore-read".to_owned();
    let name = ContentName::new(name).unwrap();
    store.put(&owner, &name, bytes).unwrap();
    store.open_read(&owner, &name).unwrap().unwrap()
}

fn read_all(reader: &mut AuthenticatedContentReader<'_, String, Engine>) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn empty_handle_reports_zero_length_and_eof() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(Blake3ObjectIdentityV1)));
    let handle = put_and_open(&store, "empty.bin", b"");
    let mut reader = AuthenticatedContentReader::new(&handle);
    assert_eq!(reader.logical_len(), 0);
    assert_eq!(reader.read(&mut [0; 8]).unwrap(), 0);
    assert_eq!(read_all(&mut reader), b"");
}

#[test]
fn small_payload_round_trips_through_read() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(Blake3ObjectIdentityV1)));
    let bytes = deterministic_bytes(4096);
    let handle = put_and_open(&store, "small.bin", &bytes);
    let mut reader = AuthenticatedContentReader::new(&handle);
    assert_eq!(reader.logical_len(), bytes.len() as u64);
    assert_eq!(read_all(&mut reader), bytes);
}

#[test]
fn cross_window_payload_round_trips_across_native_io_batches() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(Blake3ObjectIdentityV1)));
    let window = u64::try_from(crate::content::NATIVE_CONTENT_BATCH_BYTES).unwrap();
    let length = usize::try_from(window.strict_mul(2).strict_add(137)).unwrap();
    let bytes = deterministic_bytes(length);
    let handle = put_and_open(&store, "cross-window.bin", &bytes);
    let mut reader = AuthenticatedContentReader::new(&handle);
    assert_eq!(reader.logical_len(), bytes.len() as u64);
    let mut chunk = vec![0_u8; 16 * 1024];
    let mut assembled = Vec::with_capacity(bytes.len());
    loop {
        let count = reader.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        assembled.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(assembled, bytes);
}

#[test]
fn rewind_replays_exact_bytes_on_the_same_handle() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(Blake3ObjectIdentityV1)));
    let bytes = deterministic_bytes(100_003);
    let handle = put_and_open(&store, "rewind.bin", &bytes);
    let root = handle.principal_root();
    let mut reader = AuthenticatedContentReader::new(&handle);
    assert_eq!(read_all(&mut reader), bytes);
    reader.rewind();
    assert_eq!(read_all(&mut reader), bytes);
    assert_eq!(handle.principal_root(), root);
}

#[test]
fn missing_descendant_surfaces_invalid_data_not_eof() {
    let engine = Arc::new(MissingObjectEngine::new());
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "restore-read".to_owned();
    let name = ContentName::new("missing.bin").unwrap();
    let bytes = deterministic_bytes(128 * 1024);
    let outcome = store.put(&owner, &name, &bytes).unwrap();
    let file = engine
        .inner
        .object(outcome.descriptor().file())
        .expect("file object");
    let descendant = file
        .references()
        .iter()
        .find(|reference| reference.kind() == ReferenceKind::Owns)
        .expect("non-empty file owns content")
        .target();
    let handle = store.open_read(&owner, &name).unwrap().unwrap();
    engine.hide(descendant);
    let mut reader = AuthenticatedContentReader::new(&handle);
    let mut sink = [0_u8; 4096];
    let error = reader
        .read(&mut sink)
        .expect_err("missing object must fail");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_ne!(error.kind(), io::ErrorKind::UnexpectedEof);
    let message = error.to_string();
    assert!(
        message.contains("missing") || message.contains("Missing"),
        "error should retain content failure detail: {message}"
    );
}

#[test]
fn short_caller_buffers_still_deliver_exact_payload() {
    let store = PrincipalContentStore::from_engine(Arc::new(Engine::new(Blake3ObjectIdentityV1)));
    let bytes = deterministic_bytes(50_000);
    let handle = put_and_open(&store, "short-reads.bin", &bytes);
    let mut reader = AuthenticatedContentReader::new(&handle);
    let mut assembled = Vec::new();
    let mut tiny = [0_u8; 7];
    loop {
        let count = reader.read(&mut tiny).unwrap();
        if count == 0 {
            break;
        }
        assembled.extend_from_slice(&tiny[..count]);
    }
    assert_eq!(assembled, bytes);
}
