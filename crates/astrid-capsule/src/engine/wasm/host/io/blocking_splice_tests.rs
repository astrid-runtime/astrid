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

/// Parks on the flush-completion readiness, which is the second `ready`
/// call. The sizing check is the first and does not park, so a chunk written
/// before that second wait is already in `stored` when `parked` becomes true.
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

async fn wait_until_flush_is_parked(
    parked: &std::sync::atomic::AtomicBool,
    mut transfer: std::pin::Pin<&mut impl std::future::Future<Output = Result<u64, StreamError>>>,
) {
    tokio::select! {
        biased;
        result = &mut transfer => panic!("splice finished before flush completion: {result:?}"),
        () = async {
            while !parked.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        } => {}
    }
}

#[tokio::test]
async fn dropping_during_flush_completion_keeps_the_written_chunk() {
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
                hold,
                parked: std::sync::Arc::clone(&parked),
            }))
            .unwrap();
        let mut transfer = Box::pin(state.blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            3,
        ));
        wait_until_flush_is_parked(&parked, transfer.as_mut()).await;
        assert!(input.is_empty(), "the source read has already committed");
        assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
        drop(transfer);
        assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
    })
    .await;
    result.expect("drop-during-flush splice test hung");
}

#[tokio::test]
async fn cancelling_flush_completion_keeps_the_bytes_and_withholds_the_count() {
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
                hold,
                parked: std::sync::Arc::clone(&parked),
            }))
            .unwrap();
        let cancel = state.effective_cancel_token();
        let mut transfer = Box::pin(state.blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            3,
        ));
        wait_until_flush_is_parked(&parked, transfer.as_mut()).await;
        assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
        cancel.cancel();
        assert!(matches!(transfer.await, Err(StreamError::Closed)));
        assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
    })
    .await;
    result.expect("flush-cancel splice test hung");
}

/// `flush` reporting `Closed` is success once the chunk has been written.
struct ClosedOnFlush {
    stored: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::Pollable for ClosedOnFlush {
    async fn ready(&mut self) {}
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::OutputStream for ClosedOnFlush {
    fn write(&mut self, bytes: bytes::Bytes) -> Result<(), StreamError> {
        self.stored
            .lock()
            .expect("sink lock")
            .extend_from_slice(&bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Err(StreamError::Closed)
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        Ok(3)
    }
}

#[tokio::test]
async fn closed_flush_after_a_committed_write_returns_the_count() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let source = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("payload")))
        .unwrap();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let destination = state
        .resource_table
        .push::<DynOutputStream>(Box::new(ClosedOnFlush {
            stored: std::sync::Arc::clone(&stored),
        }))
        .unwrap();
    let copied = state
        .blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            7,
        )
        .await
        .expect("closed flush is success after the write");
    assert_eq!(copied, 3);
    let input = state.resource_table.get_mut(&source).unwrap();
    assert_eq!(input.read(4).unwrap().as_ref(), b"load");
    assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
}

/// Flush is accepted, then the completion wait reports `Closed`.
struct ClosedAfterFlush {
    stored: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    phase: u8,
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::Pollable for ClosedAfterFlush {
    async fn ready(&mut self) {
        self.phase = self.phase.saturating_add(1);
    }
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::OutputStream for ClosedAfterFlush {
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
        if self.phase >= 2 {
            Err(StreamError::Closed)
        } else {
            Ok(64)
        }
    }
}

#[tokio::test]
async fn closed_flush_completion_returns_the_written_count() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let source = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("pay")))
        .unwrap();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let destination = state
        .resource_table
        .push::<DynOutputStream>(Box::new(ClosedAfterFlush {
            stored: std::sync::Arc::clone(&stored),
            phase: 0,
        }))
        .unwrap();
    let copied = state
        .blocking_splice(
            Resource::new_borrow(destination.rep()),
            Resource::new_borrow(source.rep()),
            3,
        )
        .await
        .expect("closed flush completion is success after the write");
    assert_eq!(copied, 3);
    assert_eq!(stored.lock().expect("sink lock").as_slice(), b"pay");
}
