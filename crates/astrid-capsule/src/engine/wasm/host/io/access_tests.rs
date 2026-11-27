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
    assert!(sink.contents().is_empty());

    state.invocation_storage_uid = Some(owner);
    assert_eq!(state.read(src(), 2).unwrap(), b"pa");
    assert_eq!(state.skip(src(), 2).unwrap(), 2);
    assert_eq!(state.read(src(), 3).unwrap(), b"oad");
    assert_eq!(state.check_write(dst()).unwrap(), 16);
    state.write(dst(), b"data".to_vec()).unwrap();
    state.write_zeroes(dst(), 2).unwrap();
    state.flush(dst()).unwrap();
    assert_eq!(sink.contents().as_ref(), b"data\0\0");
}
