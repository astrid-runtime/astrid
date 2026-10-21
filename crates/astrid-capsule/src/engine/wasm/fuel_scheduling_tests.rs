//! Scheduler API characterization: a yield interval is not an execution allowance.

use std::future::Future;

mod checkpoints;

fn straight_line_module(engine: &wasmtime::Engine, checkpoints: bool) -> wasmtime::Module {
    let mut wat = String::from("(module (func (export \"run\") (result i32) (local $x i32)");
    for _ in 0..10_000 {
        wat.push_str("(local.set $x (i32.add (local.get $x) (i32.const 1)))");
        if checkpoints {
            wat.push_str("(loop)");
        }
    }
    wat.push_str("(local.get $x)))");
    wasmtime::Module::new(engine, wat).unwrap()
}

/// A long straight-line block may spend beyond a yield interval before returning
/// control. Reserving `interval` before polling an async call is therefore not a
/// valid hard-budget implementation. Keep this counterexample beside the engine
/// so a future scheduler does not silently substitute fairness for accounting.
#[tokio::test]
async fn async_yield_interval_is_not_a_hard_poll_fuel_ceiling() {
    let engine = super::build_wasmtime_engine().unwrap();
    let module = straight_line_module(&engine, false);
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX / 2);
    store.set_fuel(1_000_000).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let interval = 100;
    store.fuel_async_yield_interval(Some(interval)).unwrap();
    let initial = store.get_fuel().unwrap();
    let mut polls = 0_u64;
    let result = {
        let mut call = std::pin::pin!(run.call_async(&mut store, ()));
        std::future::poll_fn(|cx| {
            polls += 1;
            call.as_mut().poll(cx)
        })
        .await
        .unwrap()
    };
    let consumed = initial - store.get_fuel().unwrap();
    assert_eq!(result, 10_000);
    assert!(
        consumed > polls * interval,
        "revisit scheduler characterization: consumed={consumed}, polls={polls}, interval={interval}"
    );
    eprintln!("straight-line guest: consumed={consumed}, polls={polls}, interval={interval}");
}

#[tokio::test]
async fn finite_fuel_straight_line_characterization() {
    let engine = super::build_wasmtime_engine().unwrap();
    let module = straight_line_module(&engine, false);
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX / 2);
    store.set_fuel(100).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let result = run.call_async(&mut store, ()).await;
    eprintln!(
        "finite fuel=100: result={result:?}, remaining={:?}",
        store.get_fuel()
    );
    // Backend limitation, NOT successful enforcement: the oversized block
    // finishes and clamps remaining fuel to zero. Preserve the counterexample.
    assert_eq!(result.unwrap(), 10_000);
    assert_eq!(store.get_fuel().unwrap(), 0);
}

#[tokio::test]
async fn explicit_checkpoints_make_straight_line_fuel_exhaustion_observable() {
    let engine = super::build_wasmtime_engine().unwrap();
    let module = straight_line_module(&engine, true);
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX / 2);
    store.set_fuel(100).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let error = run.call_async(&mut store, ()).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::OutOfFuel)
    );
}

#[tokio::test]
async fn checkpointed_guest_yields_and_resumes_without_losing_state() {
    let engine = super::build_wasmtime_engine().unwrap();
    let module = straight_line_module(&engine, true);
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX / 2);
    store.set_fuel(1_000_000).unwrap();
    store.fuel_async_yield_interval(Some(100)).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let mut polls = 0_u64;
    let result = {
        let mut call = std::pin::pin!(run.call_async(&mut store, ()));
        std::future::poll_fn(|cx| {
            polls += 1;
            call.as_mut().poll(cx)
        })
        .await
        .unwrap()
    };
    assert_eq!(result, 10_000);
    assert!(polls > 300, "guest did not yield at checkpoints: {polls}");
}
