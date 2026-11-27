use crate::engine::wasm::bindings::astrid::io::streams::HostOutputStream;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use std::sync::Arc;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, StreamError};

#[tokio::test]
async fn blocking_splice_transfers_on_the_async_worker() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let source = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("payload")))
        .unwrap();
    let sink = MemoryOutputPipe::new(8);
    let destination = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let copied = state
        .blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            3,
        )
        .await
        .unwrap();
    assert_eq!(copied, 3);
    assert_eq!(sink.contents().as_ref(), b"pay");
}

#[tokio::test]
async fn cancelling_a_queued_splice_preserves_the_input() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.io_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = state.io_semaphore.clone().acquire_owned().await.unwrap();
    let input = MemoryInputPipe::new("x");
    let source = state
        .resource_table
        .push::<DynInputStream>(Box::new(input.clone()))
        .unwrap();
    let sink = MemoryOutputPipe::new(8);
    let dest = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let cancel = state.effective_cancel_token();
    let mut transfer = Box::pin(state.blocking_splice(
        Resource::new_borrow(dest.rep()),
        Resource::new_borrow(source.rep()),
        1,
    ));
    tokio::select! {
        biased;
        result = &mut transfer => panic!("completed without an I/O permit: {result:?}"),
        () = std::future::ready(()) => {}
    }
    cancel.cancel();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), transfer).await;
    assert!(
        matches!(outcome, Ok(Err(StreamError::Closed))),
        "queued splice did not observe cancellation: {outcome:?}"
    );
    assert!(!input.is_empty());
    assert!(sink.contents().is_empty());
    drop(permit);
}

/// A destination that accepts the sizing check, then parks inside the write
/// that follows a committed read. The third readiness (flush completion)
/// proceeds immediately.
struct HoldWrite {
    stored: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    phase: u8,
    hold: std::sync::Arc<tokio::sync::Notify>,
    parked: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::Pollable for HoldWrite {
    async fn ready(&mut self) {
        self.phase = self.phase.saturating_add(1);
        if self.phase == 2 {
            self.parked.store(true, std::sync::atomic::Ordering::SeqCst);
            self.hold.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::OutputStream for HoldWrite {
    fn write(&mut self, bytes: bytes::Bytes) -> Result<(), StreamError> {
        self.stored
            .lock()
            .expect("sink lock")
            .extend_from_slice(&bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        Ok(64)
    }
}

#[tokio::test]
async fn cancelling_after_a_committed_read_still_writes_the_chunk() {
    use std::sync::atomic::Ordering;

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let input = MemoryInputPipe::new("pay");
        let source = state
            .resource_table
            .push::<DynInputStream>(Box::new(input.clone()))
            .unwrap();
        let stored = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let hold = std::sync::Arc::new(tokio::sync::Notify::new());
        let parked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let destination = state
            .resource_table
            .push::<DynOutputStream>(Box::new(HoldWrite {
                stored: std::sync::Arc::clone(&stored),
                phase: 0,
                hold: std::sync::Arc::clone(&hold),
                parked: std::sync::Arc::clone(&parked),
            }))
            .unwrap();
        let cancel = state.effective_cancel_token();
        let mut transfer = Box::pin(state.blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            3,
        ));
        tokio::select! {
            biased;
            result = &mut transfer => panic!("splice finished before the write wait: {result:?}"),
            () = async {
                while !parked.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
        assert!(input.is_empty(), "the source read has already committed");
        assert!(stored.lock().expect("sink lock").is_empty());
        cancel.cancel();
        tokio::select! {
            biased;
            result = &mut transfer => panic!("cancel dropped a committed chunk: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        hold.notify_one();
        let copied = transfer.await.expect("committed chunk must be written");
        assert_eq!(copied, 3);
        assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
    })
    .await;
    result.expect("committed-read splice test hung");
}
