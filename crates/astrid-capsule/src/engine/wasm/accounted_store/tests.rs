//! Real guests exercising the production Store wrapper.

use super::*;
use crate::user_cpu::tests::accounting;
use astrid_core::PrincipalId;
use std::time::Duration;

#[tokio::test]
async fn bulk_guest_charge_survives_cancelled_reentry_and_preserves_guest_state() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module
            (memory 1)
            (global $calls (mut i32) (i32.const 0))
            (func (export "run") (result i32)
                (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
                (memory.fill (i32.const 0) (i32.const 7) (i32.const 160))
                (global.get $calls)))"#,
    )
    .unwrap();
    let initial = u64::MAX;
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX / 2);
    store.set_fuel(initial).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let mut store = AccountedStore::new(store, Some(throttle.clone())).unwrap();
    let remaining = store.meter.as_ref().unwrap().remaining.clone();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), run.call_async(&mut store, ()))
            .await
            .unwrap()
            .unwrap(),
        1
    );
    let observed = initial - remaining.load(Ordering::Relaxed);
    assert!(observed >= 160, "bulk work was not observed: {observed}");
    assert_eq!(observed, initial - store.get_fuel().unwrap());
    // Another principal spends this user's capacity before reentry. Internal
    // fuel-yield callbacks already repaid the first call's bulk-operation debt.
    let peer = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-2").unwrap(), 0)
        .await
        .unwrap();
    peer.charge(200);
    assert!(!throttle.delay().is_zero());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), run.call_async(&mut store, ()))
            .await
            .is_err()
    );
    assert_eq!(initial - remaining.load(Ordering::Relaxed), observed);
    assert!(!throttle.delay().is_zero());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), run.call_async(&mut store, ()))
            .await
            .unwrap()
            .unwrap(),
        2,
        "cancelled reentry must not execute or reset guest globals"
    );
    assert_eq!(
        initial - remaining.load(Ordering::Relaxed),
        initial - store.get_fuel().unwrap()
    );
}

#[tokio::test]
async fn compute_loop_is_rate_limited_and_drop_settles_the_final_sample() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module (func (export "run") (loop $spin (br $spin))))"#,
    )
    .unwrap();
    let mut store = wasmtime::Store::new(&engine, ());
    let initial = u64::MAX;
    store.set_fuel(initial).unwrap();
    let mut store = AccountedStore::new(store, Some(throttle.clone())).unwrap();
    let remaining = store.meter.as_ref().unwrap().remaining.clone();
    assert!(store.configure_rate_epochs(1));
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    let clock_engine = engine.clone();
    let clock = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            clock_engine.increment_epoch();
        }
    });
    let started = std::time::Instant::now();
    let result =
        tokio::time::timeout(Duration::from_millis(100), run.call_async(&mut store, ())).await;
    clock.abort();
    let _ = clock.await;
    assert!(result.is_err());
    let final_fuel = store.get_fuel().unwrap();
    // Destruction, not a test-owned settlement call, charges the final sample.
    drop(store);
    let consumed = initial - remaining.load(Ordering::Relaxed);
    assert!(consumed >= 100);
    assert_eq!(remaining.load(Ordering::Relaxed), final_fuel);
    // This guest has only unit-cost operations. Unlike a bulk operation, its
    // one-fuel sampling boundary bounds overshoot in this particular test.
    let allowance = 100 + (started.elapsed().as_secs_f64() * 100.0).ceil() as u64;
    assert!(
        consumed <= allowance + 2,
        "consumed={consumed}, allowance={allowance}"
    );
}

#[tokio::test]
async fn cancelling_inside_bulk_operation_wait_does_not_refund_its_debt() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module (memory 1)
        (func (export "run")
            (memory.fill (i32.const 0) (i32.const 7) (i32.const 4096))))"#,
    )
    .unwrap();
    let mut raw = Store::new(&engine, ());
    raw.set_epoch_deadline(u64::MAX / 2);
    raw.set_fuel(u64::MAX).unwrap();
    let mut store = AccountedStore::new(raw, Some(throttle.clone())).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), run.call_async(&mut store, ()))
            .await
            .is_err()
    );
    assert!(u64::MAX - store.get_fuel().unwrap() >= 4096);
    drop(store);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), throttle.wait())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn call_allowance_traps_without_clamping_away_bulk_debt() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module (memory 1)
        (func (export "run")
            (memory.fill (i32.const 0) (i32.const 7) (i32.const 4096))))"#,
    )
    .unwrap();
    let mut raw = Store::new(&engine, ());
    raw.set_epoch_deadline(u64::MAX / 2);
    raw.set_fuel(100).unwrap();
    let mut store = AccountedStore::new(raw, Some(throttle.clone())).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    let error = run.call_async(&mut store, ()).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::OutOfFuel)
    );
    assert!(u64::MAX - store.get_fuel().unwrap() >= 4096);
    store.set_fuel(100).unwrap();
    assert_eq!(store.get_fuel().unwrap(), u64::MAX);
    // Resetting the per-call measurement baseline cannot reset shared debt.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), throttle.wait())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn absent_user_budget_preserves_unmetered_store_and_rebinding_preserves_old_debt() {
    let accounting = accounting().await;
    let first = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let other = accounting
        .execution_throttle(&PrincipalId::new("user-2-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let mut raw = Store::new(&engine, ());
    raw.set_fuel(1000).unwrap();
    let mut store = AccountedStore::new(raw, None).unwrap();
    assert!(store.meter.is_none());
    assert_eq!(store.get_fuel().unwrap(), 1000);
    assert!(!store.configure_rate_epochs(1));
    store.bind_throttle(Some(first.clone())).unwrap();
    // Simulate a fuel sample still pending when an invocation changes owner.
    store.store.set_fuel(u64::MAX - 500).unwrap();
    store.bind_throttle(Some(other.clone())).unwrap();
    assert!(!first.delay().is_zero());
    assert!(other.delay().is_zero());
    store.bind_throttle(None).unwrap();
    store.set_fuel(1000).unwrap();
    assert_eq!(store.get_fuel().unwrap(), 1000);
    assert!(!first.delay().is_zero());
}
