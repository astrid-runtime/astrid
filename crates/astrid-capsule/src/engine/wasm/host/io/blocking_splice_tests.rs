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
    assert!(matches!(transfer.await, Err(StreamError::Closed)));
    assert!(!input.is_empty());
    assert!(sink.contents().is_empty());
    drop(permit);
}
