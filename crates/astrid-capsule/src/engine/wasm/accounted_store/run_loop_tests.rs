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
