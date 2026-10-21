//! Real WASM execution with explicitly checkpointed test guests. Production
//! guest compilation/initialization is deliberately not claimed by these tests.

use super::*;
use crate::user_cpu::execution::ExecutionAllocation;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn guest(engine: &wasmtime::Engine, increments: usize) -> wasmtime::Module {
    let mut code = String::from("(module (func (export \"run\") (result i32) (local $x i32)");
    for _ in 0..increments {
        // Each closed loop is a fuel checkpoint. No straight-line sequence
        // between checkpoints consumes more than one default fuel unit.
        code.push_str("(loop) local.get $x (loop) i32.const 1 (loop) i32.add (loop) local.set $x ");
    }
    code.push_str("(loop) local.get $x (loop)))");
    wasmtime::Module::new(engine, code).unwrap()
}

async fn execute(
    engine: &wasmtime::Engine,
    allocation: ExecutionAllocation,
    polls: &AtomicUsize,
) -> (i32, u64) {
    let module = guest(engine, 35);
    let mut store = wasmtime::Store::new(engine, ());
    store.set_fuel(1_000_000).unwrap();
    store.fuel_async_yield_interval(Some(50)).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let before = store.get_fuel().unwrap();
    let value = {
        let mut call = std::pin::pin!(run.call_async(&mut store, ()));
        let observed = std::future::poll_fn(|cx| {
            polls.fetch_add(1, Ordering::SeqCst);
            call.as_mut().poll(cx)
        });
        allocation
            .run_prepaid(NonZeroU64::new(50).unwrap(), observed)
            .await
            .unwrap()
            .unwrap()
    };
    (value, before - store.get_fuel().unwrap())
}

#[tokio::test]
async fn checkpointed_services_share_user_capacity_and_keep_guest_state() {
    let accounting = accounting().await;
    let mut config = wasmtime::Config::new();
    config
        .consume_fuel(true)
        .wasm_gc(false)
        .wasm_exceptions(false);
    #[cfg(target_os = "macos")]
    config.macos_use_mach_ports(false);
    let engine = wasmtime::Engine::new(&config).unwrap();
    let principal_ledger = FuelRateLimiter::default();
    let mut allocations = Vec::new();
    for alias in ["user-1-agent-1", "user-1-agent-2"] {
        let principal = PrincipalId::new(alias).unwrap();
        let user = accounting.resolve(&principal).await.unwrap();
        allocations.push(ExecutionAllocation::new(
            principal,
            0,
            principal_ledger.clone(),
            user,
        ));
    }
    let second = allocations.pop().unwrap();
    let first = allocations.pop().unwrap();
    let first_polls = AtomicUsize::new(0);
    let second_polls = AtomicUsize::new(0);
    let started = Instant::now();
    let (a, b) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            execute(&engine, first, &first_polls),
            execute(&engine, second, &second_polls)
        )
    })
    .await
    .expect("services should resume instead of trapping or restarting");
    assert_eq!(a.0, 35);
    assert_eq!(b.0, 35);
    let polls = first_polls.load(Ordering::SeqCst) + second_polls.load(Ordering::SeqCst);
    assert!(polls >= 6, "both guests must really yield: {polls}");
    assert!(
        a.1 + b.1 <= polls as u64 * 50,
        "consumption must fit prepaid capacity"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "shared user budget was bypassed"
    );
}

#[tokio::test]
async fn denied_prepaid_execution_never_polls_guest() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap();
    let allocation = ExecutionAllocation::new(principal, 0, FuelRateLimiter::default(), user);
    let touched = AtomicUsize::new(0);
    let result = allocation
        .run_prepaid(NonZeroU64::new(101).unwrap(), async {
            touched.fetch_add(1, Ordering::SeqCst);
        })
        .await;
    assert!(result.is_err());
    assert_eq!(touched.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bulk_memory_charge_disproves_generic_prepaid_poll_bound() {
    // Wasmtime assigns variable fuel cost to bulk operations. Checkpoints
    // around operators alone therefore do not prove a per-poll fuel bound.
    let mut config = wasmtime::Config::new();
    config
        .consume_fuel(true)
        .wasm_gc(false)
        .wasm_exceptions(false);
    #[cfg(target_os = "macos")]
    config.macos_use_mach_ports(false);
    let engine = wasmtime::Engine::new(&config).unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"
        (module
            (memory 1)
            (func (export "run")
                (loop) i32.const 0
                (loop) i32.const 42
                (loop) i32.const 4096
                (loop) memory.fill
                (loop)))
    "#,
    )
    .unwrap();
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_fuel(1_000_000).unwrap();
    store.fuel_async_yield_interval(Some(50)).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    let before = store.get_fuel().unwrap();
    let mut polls = 0;
    {
        let mut call = std::pin::pin!(run.call_async(&mut store, ()));
        std::future::poll_fn(|cx| {
            polls += 1;
            call.as_mut().poll(cx)
        })
        .await
        .unwrap();
    }
    let consumed = before - store.get_fuel().unwrap();
    assert!(
        consumed > polls * 50,
        "revisit limitation: consumed={consumed}, polls={polls}"
    );
    eprintln!("bulk memory counterexample: consumed={consumed}, polls={polls}, interval=50");
}
