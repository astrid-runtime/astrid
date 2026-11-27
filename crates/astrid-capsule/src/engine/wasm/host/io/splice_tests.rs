use crate::engine::wasm::bindings::astrid::io::streams::HostOutputStream;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, StreamError};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn splice_binds_both_handles_and_length_after_owner_admission() {
    for blocking in [false, true] {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let source = state
            .resource_table
            .push::<DynInputStream>(Box::new(MemoryInputPipe::new("selected")))
            .unwrap();
        let other = state
            .resource_table
            .push::<DynInputStream>(Box::new(MemoryInputPipe::new("other")))
            .unwrap();
        let sink = MemoryOutputPipe::new(32);
        let dest = state
            .resource_table
            .push::<DynOutputStream>(Box::new(sink.clone()))
            .unwrap();
        let spare_sink = MemoryOutputPipe::new(32);
        let spare = state
            .resource_table
            .push::<DynOutputStream>(Box::new(spare_sink.clone()))
            .unwrap();

        state.invocation_storage_uid = Some(astrid_core::PrincipalUid::from_bytes([99; 32]));
        assert!(matches!(
            call(
                blocking,
                &mut state,
                Resource::new_borrow(dest.rep()),
                Resource::new_borrow(source.rep()),
                3
            )
            .await,
            Err(StreamError::Closed)
        ));
        assert!(sink.contents().is_empty());
        state.invocation_storage_uid = Some(
            state
                .principal_directory
                .uid_for(&state.effective_principal())
                .unwrap(),
        );
        assert_eq!(
            call(
                blocking,
                &mut state,
                Resource::new_borrow(dest.rep()),
                Resource::new_borrow(source.rep()),
                3
            )
            .await
            .unwrap(),
            3
        );
        assert_eq!(sink.contents().as_ref(), b"sel");
        assert!(spare_sink.contents().is_empty());
        assert_eq!(
            call(
                blocking,
                &mut state,
                Resource::new_borrow(spare.rep()),
                Resource::new_borrow(other.rep()),
                2
            )
            .await
            .unwrap(),
            2
        );
        assert_eq!(spare_sink.contents().as_ref(), b"ot");
    }
}

async fn call(
    blocking: bool,
    state: &mut crate::engine::wasm::host_state::HostState,
    dst: Resource<DynOutputStream>,
    src: Resource<DynInputStream>,
    len: u64,
) -> Result<u64, StreamError> {
    if blocking {
        state.blocking_splice(dst, src, len).await
    } else {
        state.splice(dst, src, len)
    }
}

#[tokio::test]
async fn queued_splice_refuses_a_rebound_owner_before_touching_either_stream() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let directory = state.principal_directory.clone();
    let principal = state.effective_principal();
    let uid = directory.uid_for(&principal).unwrap();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    state.io_semaphore = semaphore;
    let input = MemoryInputPipe::new("keep");
    let src = state
        .resource_table
        .push::<DynInputStream>(Box::new(input.clone()))
        .unwrap();
    let sink = MemoryOutputPipe::new(16);
    let dst = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let mut transfer = Box::pin(state.blocking_splice(
        Resource::new_borrow(dst.rep()),
        Resource::new_borrow(src.rep()),
        4,
    ));
    tokio::select! {
        biased;
        result = &mut transfer => panic!("completed before permit release: {result:?}"),
        () = std::future::ready(()) => {}
    }
    directory
        .rename(
            uid,
            &principal,
            astrid_core::PrincipalId::new("renamed").unwrap(),
        )
        .unwrap();
    drop(permit);
    assert!(matches!(transfer.await, Err(StreamError::Closed)));
    assert_eq!(
        wasmtime_wasi::p2::InputStream::read(&mut input.clone(), 4)
            .unwrap()
            .as_ref(),
        b"keep"
    );
    assert!(sink.contents().is_empty());
}

#[tokio::test]
async fn retiring_a_registered_device_drains_a_queued_transfer_without_consuming_input() {
    use std::sync::Arc;
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let principal = state.effective_principal();
    let temp = tempfile::tempdir().unwrap();
    let key_id =
        crate::engine::wasm::test_fixtures::register_stream_caller(&mut state, temp.path());
    let sessions = state.device_sessions.clone();
    let tracker = Arc::new(crate::engine::wasm::PrincipalInvocationTracker::default());
    state.principal_invocations = Some(tracker.clone());
    state.io_semaphore = Arc::new(tokio::sync::Semaphore::new(0));
    let mut input = MemoryInputPipe::new("keep");
    let src = state
        .resource_table
        .push::<DynInputStream>(Box::new(input.clone()))
        .unwrap();
    let sink = MemoryOutputPipe::new(16);
    let dst = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let mut transfer = Box::pin(state.blocking_splice(
        Resource::new_borrow(dst.rep()),
        Resource::new_borrow(src.rep()),
        4,
    ));
    tokio::select! {
        biased;
        result = &mut transfer => panic!("expected queued transfer, got {result:?}"),
        () = std::future::ready(()) => {}
    }
    let mut retirement = Box::pin(sessions.retire(&principal, &key_id));
    tokio::select! {
        biased;
        result = &mut retirement => panic!("expected live device session, got {result:?}"),
        () = std::future::ready(()) => {}
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        assert!(matches!(transfer.await, Err(StreamError::Closed)));
        retirement.await.unwrap();
    })
    .await
    .expect("device retirement must drain the queued transfer");
    tracker.retire(&principal);
    assert!(matches!(
        state.splice(
            Resource::new_borrow(dst.rep()),
            Resource::new_borrow(src.rep()),
            4
        ),
        Err(StreamError::Closed)
    ));
    assert_eq!(
        wasmtime_wasi::p2::InputStream::read(&mut input, 4)
            .unwrap()
            .as_ref(),
        b"keep"
    );
    assert!(sink.contents().is_empty());
}

#[tokio::test]
async fn blocking_splice_withholds_its_count_if_the_owner_changes_during_io() {
    use tokio::io::AsyncWriteExt;
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let principal = state.effective_principal();
    let directory = state.principal_directory.clone();
    let uid = directory.uid_for(&principal).unwrap();
    let (reader, mut producer) = tokio::io::duplex(16);
    let input = wasmtime_wasi::p2::pipe::AsyncReadStream::new(reader);
    let src = state
        .resource_table
        .push::<DynInputStream>(Box::new(input))
        .unwrap();
    let sink = MemoryOutputPipe::new(16);
    let dst = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let mut transfer = Box::pin(state.blocking_splice(
        Resource::new_borrow(dst.rep()),
        Resource::new_borrow(src.rep()),
        4,
    ));
    tokio::select! {
        biased;
        result = &mut transfer => panic!("expected a pending source read: {result:?}"),
        () = std::future::ready(()) => {}
    }
    directory
        .rename(
            uid,
            &principal,
            astrid_core::PrincipalId::new("after").unwrap(),
        )
        .unwrap();
    producer.write_all(b"sent").await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), transfer)
        .await
        .unwrap();
    assert!(matches!(result, Err(StreamError::Closed)));
    assert_eq!(sink.contents().as_ref(), b"sent");
}
