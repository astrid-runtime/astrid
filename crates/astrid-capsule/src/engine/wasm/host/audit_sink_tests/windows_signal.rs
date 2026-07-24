//! Windows signal-audit denial regressions.

use super::*;

#[tokio::test]
async fn windows_closed_handle_unsupported_signal_is_denied_once() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
        ErrorCode, HostProcessHandle as _, ProcessHandle, ProcessSignal,
    };
    use wasmtime::component::Resource;

    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    for signal in [
        ProcessSignal::Hup,
        ProcessSignal::Usr1,
        ProcessSignal::Usr2,
        ProcessSignal::Int,
        ProcessSignal::Stop,
        ProcessSignal::Cont,
    ] {
        let result = state.signal(Resource::<ProcessHandle>::new_borrow(u32::MAX), signal);
        assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    }

    let records = sink.snapshot();
    assert_eq!(
        records.len(),
        6,
        "each signal denial must report exactly once"
    );
    assert!(records.iter().all(|(_, event, outcome)| matches!(
        (event, outcome),
        (
            CapturedEvent::ProcessSignal(process, _),
            CapturedOutcome::Denied(_)
        ) if process == "process-handle"
    )));
}

#[tokio::test]
async fn windows_missing_persistent_unsupported_signal_is_denied_once() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
        ErrorCode, Host as _, ProcessSignal,
    };

    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    for signal in [
        ProcessSignal::Hup,
        ProcessSignal::Usr1,
        ProcessSignal::Usr2,
        ProcessSignal::Int,
        ProcessSignal::Stop,
        ProcessSignal::Cont,
    ] {
        let result = state.signal("already-exited-or-foreign".to_string(), signal);
        assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    }

    let records = sink.snapshot();
    assert_eq!(
        records.len(),
        6,
        "each signal denial must report exactly once"
    );
    assert!(records.iter().all(|(_, event, outcome)| matches!(
        (event, outcome),
        (
            CapturedEvent::ProcessSignal(process, _),
            CapturedOutcome::Denied(_)
        ) if process.starts_with("persistent:")
    )));
}
