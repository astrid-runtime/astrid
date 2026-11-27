use crate::engine::wasm::bindings::astrid::io::{
    error::HostError,
    poll::HostPollable,
    streams::{HostInputStream, HostOutputStream},
};
use crate::engine::wasm::test_fixtures::minimal_host_state;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream};

#[tokio::test]
async fn a_live_subscription_keeps_its_stream_until_the_child_is_released() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let stream = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("buffer")))
        .unwrap();
    let rep = stream.rep();
    let child = HostInputStream::subscribe(&mut state, Resource::new_borrow(rep)).unwrap();
    let output = state
        .resource_table
        .push::<DynOutputStream>(Box::new(MemoryOutputPipe::new(32)))
        .unwrap();
    let error = state
        .resource_table
        .push(wasmtime::format_err!("sample"))
        .unwrap();
    state.effective_cancel_token().cancel();
    let failure = HostInputStream::drop(&mut state, stream).await.unwrap_err();
    assert!(matches!(
        failure.downcast_ref::<wasmtime::component::ResourceTableError>(),
        Some(wasmtime::component::ResourceTableError::HasChildren)
    ));
    assert!(state.resource_table.get(&child).is_ok());
    HostPollable::drop(&mut state, child).unwrap();
    assert!(
        state
            .resource_table
            .get(&Resource::<DynInputStream>::new_borrow(rep))
            .is_ok()
    );
    HostInputStream::drop(&mut state, Resource::new_own(rep))
        .await
        .unwrap();
    assert!(state.resource_table.get(&output).is_ok());
    HostOutputStream::drop(&mut state, output).await.unwrap();
    assert!(state.resource_table.get(&error).is_ok());
    HostError::drop(&mut state, error).unwrap();
    assert!(state.resource_table.is_empty());
}

#[tokio::test]
async fn owned_placeholder_pollable_releases_its_private_parent() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let child = super::super::stubs::always_ready_pollable(&mut state.resource_table).unwrap();
    HostPollable::drop(&mut state, child).unwrap();
    assert!(state.resource_table.is_empty());
}

/// Model an input backend whose cleanup cannot finish until its worker drains.
struct DrainingInput(tokio::sync::oneshot::Receiver<()>);

#[async_trait::async_trait]
impl wasmtime_wasi::p2::Pollable for DrainingInput {
    async fn ready(&mut self) {}
}

#[async_trait::async_trait]
impl wasmtime_wasi::p2::InputStream for DrainingInput {
    fn read(&mut self, _: usize) -> Result<bytes::Bytes, wasmtime_wasi::p2::StreamError> {
        Err(wasmtime_wasi::p2::StreamError::Closed)
    }

    async fn cancel(&mut self) {
        (&mut self.0).await.expect("worker completes cleanup");
    }
}

#[tokio::test]
async fn input_destruction_finishes_only_after_its_backend_drains() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let (worker, done) = tokio::sync::oneshot::channel();
    let input = state
        .resource_table
        .push::<DynInputStream>(Box::new(DrainingInput(done)))
        .unwrap();
    let mut closing = Box::pin(HostInputStream::drop(&mut state, input));
    tokio::select! {
        biased;
        result = &mut closing => panic!("cleanup returned before the backend drained: {result:?}"),
        () = std::future::ready(()) => {}
    }
    worker.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), closing)
        .await
        .unwrap()
        .unwrap();
    assert!(state.resource_table.is_empty());
}
