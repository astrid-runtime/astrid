//! Exercise the same run-loop scheduler setup used when loading capsules.
use super::super::{HostState, RunLoopBudget, build_wasmtime_engine, test_fixtures};
use super::*;
use astrid_core::PrincipalId;

async fn run(cooperative: bool, window: Option<u64>) -> wasmtime::Result<()> {
    let accounting = crate::user_cpu::tests::accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module
        (import "host" "tick" (func $tick))
        (func (export "run") (local $left i32)
            (local.set $left (i32.const 6))
            (loop $again
                call $tick
                (local.set $left (i32.sub (local.get $left) (i32.const 1)))
                (br_if $again (local.get $left)))))"#,
    )
    .unwrap();
    let state = test_fixtures::minimal_host_state(tokio::runtime::Handle::current());
    let mut raw = Store::new(&engine, state);
    raw.set_fuel(u64::MAX).unwrap();
    let mut store = AccountedStore::new(raw, Some(throttle)).unwrap();
    store.configure_run_epochs(&RunLoopBudget {
        exempt: window.is_none(),
        bound_run_loop: window.is_some(),
        window_ticks: window,
        mem_bytes: 65_536,
    });
    let mut linker = wasmtime::Linker::new(&engine);
    let clock = engine.clone();
    linker
        .func_wrap(
            "host",
            "tick",
            move |mut caller: wasmtime::Caller<'_, HostState>| {
                caller.data_mut().recv_yielded = cooperative;
                clock.increment_epoch();
            },
        )
        .unwrap();
    let instance = linker.instantiate_async(&mut store, &module).await.unwrap();
    let function = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        function.call_async(&mut store, ()),
    )
    .await
    .expect("run-loop test must terminate")
}

#[tokio::test]
async fn accounted_run_loop_preserves_runaway_interrupt() {
    let error = run(false, Some(1))
        .await
        .expect_err("non-cooperative run loop must interrupt");
    assert_eq!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::Interrupt)
    );
}

#[tokio::test]
async fn accounted_run_loop_preserves_cooperative_and_exempt_execution() {
    run(true, Some(1)).await.unwrap();
    run(false, None).await.unwrap();
}

#[tokio::test]
async fn accounted_run_loop_does_not_shorten_watchdog_windows() {
    // Six sampling ticks are fewer than three four-tick watchdog windows.
    run(false, Some(4)).await.unwrap();
}

const COMPONENT_SPINNER: &str = r#"(component
  (core module $m (func (export "run") (loop $forever (br $forever))))
  (core instance $i (instantiate $m))
  (func (export "run") (canon lift (core func $i "run"))))"#;

fn exempt_budget() -> RunLoopBudget {
    RunLoopBudget {
        exempt: true,
        bound_run_loop: false,
        window_ticks: None,
        mem_bytes: 65_536,
    }
}

fn engine_with_instance_token(
    instance: tokio_util::sync::CancellationToken,
) -> super::super::WasmEngine {
    let mut engine = super::super::WasmEngine::new(
        toml::from_str("[package]\nname = 'accounted-debt-wait'\nversion = '0.0.1'")
            .expect("manifest"),
        std::path::PathBuf::new(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        super::super::limits::CapsuleRuntimeLimits::default(),
        super::super::limits::HttpLimits::default(),
    );
    engine.cancel_token = Some(instance);
    engine
}

/// Overlay cancel of Alice must not trap an AccountedStore shared pump.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accounted_component_spinner_survives_principal_overlay_cancel() {
    let accounting = crate::user_cpu::tests::accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = build_wasmtime_engine().unwrap();
    let component = wasmtime::component::Component::new(&engine, COMPONENT_SPINNER).unwrap();

    let mut state = test_fixtures::minimal_host_state(tokio::runtime::Handle::current());
    state.system_runtime = true;
    let alice = PrincipalId::new("alice").unwrap();
    state.install_invocation_cancel_token(Some(&alice));
    let parent = state.cancel_token.clone();
    let tokens = state.principal_cancel_tokens.clone();

    let mut raw = Store::new(&engine, state);
    raw.set_fuel(u64::MAX).unwrap();
    let mut store = AccountedStore::new(raw, Some(throttle)).unwrap();
    store.configure_run_epochs(&exempt_budget());

    let linker = wasmtime::component::Linker::<HostState>::new(&engine);
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();

    let ticker =
        super::super::spawn_epoch_ticker_every(&engine, std::time::Duration::from_millis(1));
    super::super::cancel_principal_token(&tokens, &parent, &alice);
    let overlay = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        run.call_async(&mut store, ()),
    )
    .await;
    drop(ticker);
    assert!(
        overlay.is_err(),
        "principal overlay cancel must not trap an accounted shared pump: {overlay:?}"
    );
}

// Observe the real Store immediately before AccountedStore's Drop settles it.
struct FinalFuelObservation {
    store: AccountedStore<HostState>,
    final_fuel: Arc<AtomicU64>,
}

impl Drop for FinalFuelObservation {
    fn drop(&mut self) {
        self.final_fuel
            .store(self.store.get_fuel().unwrap_or(0), Ordering::Relaxed);
    }
}

/// Production run workers race instance cancel against `call_async` with the
/// same biased `select!` as `wasm/mod.rs` (~2828), then `unload` aborts/joins.
///
/// Accounted sampling still `YieldCustom(throttle.wait())` before the 50-tick
/// watchdog, so a direct `call_async` can sit in debt wait for ~100s. The run
/// loop must not wait that out: dropping `call_async` (Wasmtime cancels the
/// in-flight yield) plus `unload` abort/join has to finish inside the existing
/// 10s cleanup bound, and Drop must keep the last fuel sample and the unpaid
/// debt. This does not claim epoch Interrupt preempts `wait()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accounted_run_loop_unload_cancels_mid_throttle_wait_and_retains_debt() {
    use crate::engine::ExecutionEngine;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let accounting = crate::user_cpu::tests::accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let peer = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-2").unwrap(), 0)
        .await
        .unwrap();
    let wasm = build_wasmtime_engine().unwrap();
    let component = wasmtime::component::Component::new(&wasm, COMPONENT_SPINNER).unwrap();

    let state = test_fixtures::minimal_host_state(tokio::runtime::Handle::current());
    let cancel = state.cancel_token.clone();
    let mut raw = Store::new(&wasm, state);
    raw.set_fuel(u64::MAX).unwrap();
    let mut store = AccountedStore::new(raw, Some(throttle.clone())).unwrap();
    let remaining = store.meter.as_ref().unwrap().remaining.clone();
    store.configure_run_epochs(&exempt_budget());

    let linker = wasmtime::component::Linker::<HostState>::new(&wasm);
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();

    let before_run = remaining.load(Ordering::Relaxed);
    let final_fuel = Arc::new(AtomicU64::new(0));
    let mut observed = FinalFuelObservation {
        store,
        final_fuel: final_fuel.clone(),
    };
    let mut engine = engine_with_instance_token(cancel.clone());
    engine.wasmtime_engine = Some(wasm.clone());
    let ticker = super::super::spawn_epoch_ticker_every(&wasm, Duration::from_millis(1));
    engine.run_handles.push(tokio::task::spawn(async move {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {}
            result = run.call_async(&mut observed.store, ()) => {
                let _ = result;
            }
        }
    }));

    // Observe actual guest fuel consumption, rather than assuming a sleep
    // means the worker reached the accounting wait. Debt remains outstanding.
    tokio::time::timeout(Duration::from_secs(10), async {
        while remaining.load(Ordering::Relaxed) == before_run {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guest must reach a charged execution sample before unload");
    // Charging after observed guest execution avoids mistaking the entry
    // call-hook's pre-guest debt wait for a running guest's sampling wait.
    // accounting() user ceiling is 100 fuel/s. 10_000 fuel is ~100s of wait()
    // loops (delay() itself wakes at most once per second). That outlasts the
    // 10s cleanup bound; finishing inside 10s cannot be "wait repaid the debt".
    peer.charge(10_000);
    assert!(
        !throttle.delay().is_zero(),
        "precondition: unload must face outstanding user debt"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), throttle.wait())
            .await
            .is_err(),
        "precondition: remaining wait must exceed a sampling tick"
    );

    let started = Instant::now();
    engine
        .unload()
        .await
        .expect("unload must cancel/abort/join mid-wait");
    drop(ticker);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "unload must finish inside the 10s cleanup bound while ~100s of debt remains: {elapsed:?}"
    );

    let final_fuel = final_fuel.load(Ordering::Relaxed);
    assert_ne!(final_fuel, 0, "worker must drop its observed Store");
    assert_eq!(
        remaining.load(Ordering::Relaxed),
        final_fuel,
        "Drop must settle the final observable fuel sample exactly"
    );
    assert!(
        !throttle.delay().is_zero(),
        "unload must not refund already charged user debt"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), throttle.wait())
            .await
            .is_err(),
        "remaining debt must still require waiting after unload"
    );
}
