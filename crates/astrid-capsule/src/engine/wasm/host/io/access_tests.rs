use crate::engine::wasm::bindings::astrid::io::streams::{HostInputStream, HostOutputStream};
use crate::engine::wasm::test_fixtures::minimal_host_state;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, StreamError};

#[tokio::test]
async fn immediate_operations_preserve_the_streams_on_owner_refusal() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let input = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("payload")))
        .unwrap();
    let sink = MemoryOutputPipe::new(16);
    let output = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let src = || Resource::new_borrow(input.rep());
    let dst = || Resource::new_borrow(output.rep());
    let owner = state
        .principal_directory
        .uid_for(&state.effective_principal())
        .unwrap();
    state.invocation_storage_uid = Some(astrid_core::PrincipalUid::from_bytes([99; 32]));

    assert!(matches!(state.read(src(), 2), Err(StreamError::Closed)));
    assert!(matches!(state.skip(src(), 2), Err(StreamError::Closed)));
    assert!(matches!(state.check_write(dst()), Err(StreamError::Closed)));
    assert!(matches!(
        state.write(dst(), b"private".to_vec()),
        Err(StreamError::Closed)
    ));
    assert!(matches!(state.flush(dst()), Err(StreamError::Closed)));
    assert!(matches!(
        state.write_zeroes(dst(), 2),
        Err(StreamError::Closed)
    ));
    assert!(HostInputStream::subscribe(&mut state, src()).is_err());
    assert!(HostOutputStream::subscribe(&mut state, dst()).is_err());
    assert!(sink.contents().is_empty());

    state.invocation_storage_uid = Some(owner);
    let input_ready = HostInputStream::subscribe(&mut state, src()).unwrap();
    let output_ready = HostOutputStream::subscribe(&mut state, dst()).unwrap();
    assert_ne!(input_ready.rep(), output_ready.rep());
    assert!(state.resource_table.get(&input_ready).is_ok());
    assert!(state.resource_table.get(&output_ready).is_ok());
    assert_eq!(state.read(src(), 2).unwrap(), b"pa");
    assert_eq!(state.skip(src(), 2).unwrap(), 2);
    assert_eq!(state.read(src(), 3).unwrap(), b"oad");
    assert_eq!(state.check_write(dst()).unwrap(), 16);
    state.write(dst(), b"data".to_vec()).unwrap();
    state.write_zeroes(dst(), 2).unwrap();
    state.flush(dst()).unwrap();
    assert_eq!(sink.contents().as_ref(), b"data\0\0");
}

#[tokio::test]
async fn blocking_stream_methods_bind_the_owner_and_use_the_admitted_operands() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let input = state
        .resource_table
        .push::<DynInputStream>(Box::new(MemoryInputPipe::new("payload")))
        .unwrap();
    let sink = MemoryOutputPipe::new(32);
    let output = state
        .resource_table
        .push::<DynOutputStream>(Box::new(sink.clone()))
        .unwrap();
    let src = || Resource::new_borrow(input.rep());
    let dst = || Resource::new_borrow(output.rep());
    let uid = state
        .principal_directory
        .uid_for(&state.effective_principal())
        .unwrap();
    state.invocation_storage_uid = Some(astrid_core::PrincipalUid::from_bytes([99; 32]));
    assert!(matches!(
        state.blocking_read(src(), 2).await,
        Err(StreamError::Closed)
    ));
    assert!(matches!(
        state.blocking_skip(src(), 2).await,
        Err(StreamError::Closed)
    ));
    assert!(matches!(
        state
            .blocking_write_and_flush(dst(), b"private".to_vec())
            .await,
        Err(StreamError::Closed)
    ));
    assert!(matches!(
        state.blocking_flush(dst()).await,
        Err(StreamError::Closed)
    ));
    assert!(matches!(
        state.blocking_write_zeroes_and_flush(dst(), 2).await,
        Err(StreamError::Closed)
    ));
    assert!(sink.contents().is_empty());
    state.invocation_storage_uid = Some(uid);
    assert_eq!(state.blocking_read(src(), 2).await.unwrap(), b"pa");
    assert_eq!(state.blocking_skip(src(), 2).await.unwrap(), 2);
    assert_eq!(state.blocking_read(src(), 3).await.unwrap(), b"oad");
    state
        .blocking_write_and_flush(dst(), b"data".to_vec())
        .await
        .unwrap();
    state
        .blocking_write_zeroes_and_flush(dst(), 2)
        .await
        .unwrap();
    state.blocking_flush(dst()).await.unwrap();
    assert_eq!(sink.contents().as_ref(), b"data\0\0");
}

#[tokio::test]
async fn rebound_owner_cannot_receive_a_pending_blocking_read() {
    use tokio::io::AsyncWriteExt;
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let principal = state.effective_principal();
    let directory = state.principal_directory.clone();
    let uid = directory.uid_for(&principal).unwrap();
    let (reader, mut writer) = tokio::io::duplex(16);
    let source = wasmtime_wasi::p2::pipe::AsyncReadStream::new(reader);
    let input = state
        .resource_table
        .push::<DynInputStream>(Box::new(source))
        .unwrap();
    let mut read = Box::pin(state.blocking_read(Resource::new_borrow(input.rep()), 4));
    tokio::select! {
        biased;
        value = &mut read => panic!("expected pending input, got {value:?}"),
        () = std::future::ready(()) => {}
    }
    directory
        .rename(
            uid,
            &principal,
            astrid_core::PrincipalId::new("renamed").unwrap(),
        )
        .unwrap();
    writer.write_all(b"keep").await.unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), read)
        .await
        .unwrap();
    assert!(matches!(outcome, Err(StreamError::Closed)));
}

#[tokio::test]
async fn cancellation_and_retirement_after_capture_refuse_the_immediate_sink() {
    use super::authority::Authority;
    use wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream as WasiOutput;
    for retire_device in [false, true] {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let temp = tempfile::tempdir().unwrap();
        let key =
            crate::engine::wasm::test_fixtures::register_stream_caller(&mut state, temp.path());
        let sink = MemoryOutputPipe::new(16);
        let output = state
            .resource_table
            .push::<DynOutputStream>(Box::new(sink.clone()))
            .unwrap();
        let admission = Authority::capture(&state).unwrap();
        let cancel = state.effective_cancel_token();
        let sessions = state.device_sessions.clone();
        let principal = state.effective_principal();
        let mut retirement = Box::pin(sessions.retire(&principal, &key));
        if retire_device {
            tokio::select! {
                biased;
                result = &mut retirement => panic!("expected admitted device, got {result:?}"),
                () = std::future::ready(()) => {}
            }
        } else {
            cancel.cancel();
        }
        assert!(matches!(
            admission.start(
                &state.principal_directory,
                &cancel,
                &mut state.resource_table,
                Resource::new_borrow(output.rep()),
                b"data".to_vec(),
                WasiOutput::write
            ),
            Err(StreamError::Closed)
        ));
        assert!(sink.contents().is_empty());
        drop(admission);
        if retire_device {
            retirement.await.unwrap();
        }
    }
}

#[tokio::test]
async fn queued_single_stream_access_rechecks_the_owner_before_consuming_or_writing() {
    for write in [false, true] {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let principal = state.effective_principal();
        let directory = state.principal_directory.clone();
        let uid = directory.uid_for(&principal).unwrap();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = sem.clone().acquire_owned().await.unwrap();
        state.io_semaphore = sem;
        let mut input = MemoryInputPipe::new("keep");
        let source = state
            .resource_table
            .push::<DynInputStream>(Box::new(input.clone()))
            .unwrap();
        let sink = MemoryOutputPipe::new(16);
        let destination = state
            .resource_table
            .push::<DynOutputStream>(Box::new(sink.clone()))
            .unwrap();
        let mut work = Box::pin(async {
            if write {
                state
                    .blocking_write_and_flush(
                        Resource::new_borrow(destination.rep()),
                        b"data".to_vec(),
                    )
                    .await
            } else {
                state
                    .blocking_read(Resource::new_borrow(source.rep()), 4)
                    .await
                    .map(drop)
            }
        });
        tokio::select! {
            biased;
            result = &mut work => panic!("expected a pending capacity wait: {result:?}"),
            () = std::future::ready(()) => {}
        }
        directory
            .rename(
                uid,
                &principal,
                astrid_core::PrincipalId::new("after").unwrap(),
            )
            .unwrap();
        drop(permit);
        assert!(matches!(work.await, Err(StreamError::Closed)));
        assert_eq!(
            wasmtime_wasi::p2::InputStream::read(&mut input, 4)
                .unwrap()
                .as_ref(),
            b"keep"
        );
        assert!(sink.contents().is_empty());
    }
}

#[tokio::test]
async fn cancellation_and_device_retirement_wake_a_pending_stream_read() {
    for retire_device in [false, true] {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let temp = tempfile::tempdir().unwrap();
        let key =
            crate::engine::wasm::test_fixtures::register_stream_caller(&mut state, temp.path());
        let principal = state.effective_principal();
        let sessions = state.device_sessions.clone();
        let cancel = state.effective_cancel_token();
        let (reader, _writer) = tokio::io::duplex(16);
        let input = state
            .resource_table
            .push::<DynInputStream>(Box::new(wasmtime_wasi::p2::pipe::AsyncReadStream::new(
                reader,
            )))
            .unwrap();
        let mut read = Box::pin(state.blocking_read(Resource::new_borrow(input.rep()), 4));
        tokio::select! {
            biased;
            result = &mut read => panic!("expected pending read: {result:?}"),
            () = std::future::ready(()) => {}
        }
        let mut retirement = Box::pin(sessions.retire(&principal, &key));
        if retire_device {
            tokio::select! {
                biased;
                result = &mut retirement => panic!("expected admitted read: {result:?}"),
                () = std::future::ready(()) => {}
            }
        } else {
            cancel.cancel();
        }
        let timeout = std::time::Duration::from_secs(5);
        let outcome = tokio::time::timeout(timeout, read).await.unwrap();
        assert!(matches!(outcome, Err(StreamError::Closed)));
        if retire_device {
            tokio::time::timeout(timeout, retirement)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
