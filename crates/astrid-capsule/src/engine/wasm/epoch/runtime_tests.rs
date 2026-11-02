//! Public runtime regressions for instance-only epoch Interrupt.
//!
//! `request_cancel_for` must leave a shared run pump `check_health` Ready.
//! Unload still completes by cancelling the instance token. These tests drive
//! the production Store callback and the public `ExecutionEngine` methods.

use std::time::Duration;

use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use super::super::host_state::HostState;
use super::super::test_fixtures::minimal_host_state;
use super::super::{RunLoopBudget, WASM_MAX_MEMORY_BYTES, WasmEngine, spawn_epoch_ticker_every};
use super::{EpochAction, configure_run_store, run_epoch_action};
use crate::capsule::CapsuleState;
use crate::engine::ExecutionEngine;
use crate::engine::wasm::limits;

const SPINNER: &str = r#"(component
  (core module $m (func (export "run") (loop $forever (br $forever))))
  (core instance $i (instantiate $m))
  (func (export "run") (canon lift (core func $i "run"))))"#;

fn alice() -> astrid_core::PrincipalId {
    astrid_core::PrincipalId::new("alice").expect("fixture principal")
}

fn exempt_budget() -> RunLoopBudget {
    RunLoopBudget {
        exempt: true,
        bound_run_loop: false,
        window_ticks: None,
        mem_bytes: WASM_MAX_MEMORY_BYTES,
    }
}

fn engine_with_shared_tokens(
    instance: tokio_util::sync::CancellationToken,
    tokens: super::super::host_state::PrincipalCancelTokens,
) -> WasmEngine {
    let mut engine = WasmEngine::new(
        toml::from_str("[package]\nname = 'epoch-overlay-pump'\nversion = '0.0.1'")
            .expect("manifest"),
        std::path::PathBuf::new(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        limits::CapsuleRuntimeLimits::default(),
        limits::HttpLimits::default(),
    );
    engine.system_runtime = true;
    engine.cancel_token = Some(instance);
    engine.principal_cancel_tokens = Some(tokens);
    engine
}

/// `request_cancel_for(alice)` on a spinning SystemResident pump must not
/// finish the worker. Current `effective_cancel_token` Interrupt fails this
/// with `check_health == Failed` after the first watchdog window. Unload still
/// completes by cancelling the instance token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_cancel_for_principal_leaves_shared_pump_ready_and_unload_completes() {
    let wasm = super::super::build_wasmtime_engine().expect("engine");
    let component = Component::new(&wasm, SPINNER).expect("component");

    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.system_runtime = true;
    let instance = state.cancel_token.clone();
    let tokens = state.principal_cancel_tokens.clone();
    let alice = alice();
    state.install_invocation_cancel_token(Some(&alice));
    assert_ne!(
        run_epoch_action(&mut state, None),
        EpochAction::Interrupt,
        "precondition: live instance must not already Interrupt"
    );

    let mut store = Store::new(&wasm, state);
    store.set_fuel(u64::MAX).expect("fuel");
    configure_run_store(&mut store, &exempt_budget());

    let linker = Linker::<HostState>::new(&wasm);
    let instance_wasm = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instantiate");
    let run = instance_wasm
        .get_typed_func::<(), ()>(&mut store, "run")
        .expect("run export");

    let mut engine = engine_with_shared_tokens(instance.clone(), tokens);
    engine.wasmtime_engine = Some(wasm.clone());
    let ticker = spawn_epoch_ticker_every(&wasm, Duration::from_millis(1));
    engine.run_handles.push(tokio::task::spawn(async move {
        let _ = run.call_async(&mut store, ()).await;
    }));

    engine.request_cancel_for(&alice);
    assert!(
        !instance.is_cancelled(),
        "request_cancel_for must not cancel the instance token"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        engine.check_health(),
        CapsuleState::Ready,
        "principal overlay cancel must not finish the shared run worker"
    );
    assert!(
        engine
            .run_handles
            .iter()
            .all(|handle| !handle.is_finished()),
        "shared pump JoinHandle must still be running after request_cancel_for"
    );

    let started = std::time::Instant::now();
    engine
        .unload()
        .await
        .expect("unload must complete after instance cancel");
    drop(ticker);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "unload must join within the existing 10s cleanup bound: {:?}",
        started.elapsed()
    );
}
