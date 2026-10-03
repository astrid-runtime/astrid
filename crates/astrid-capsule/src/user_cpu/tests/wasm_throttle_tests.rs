//! Exercise debt at real guest/host boundaries before wiring the production
//! scheduler. This is a scheduler prototype, not production-path coverage.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone)]
struct BoundaryMeter {
    remaining: Arc<AtomicU64>,
    charged: Arc<AtomicU64>,
    throttle: super::super::throttle::ExecutionThrottle,
}

impl BoundaryMeter {
    fn observe(&self, remaining: u64) -> wasmtime::Result<()> {
        let previous = self.remaining.swap(remaining, Ordering::Relaxed);
        let spent = previous.checked_sub(remaining).ok_or_else(|| {
            wasmtime::Error::msg("fuel reset without resetting the accounting baseline")
        })?;
        self.charged.fetch_add(spent, Ordering::Relaxed);
        self.throttle.charge(spent);
        Ok(())
    }
}

#[async_trait::async_trait]
impl wasmtime::CallHookHandler<()> for BoundaryMeter {
    async fn handle_call_event(
        &self,
        store: wasmtime::StoreContextMut<'_, ()>,
        event: wasmtime::CallHook,
    ) -> wasmtime::Result<()> {
        self.observe(store.get_fuel()?)?;
        if event.exiting_host() {
            self.throttle.wait().await;
        }
        Ok(())
    }
}

#[tokio::test]
async fn bulk_guest_charge_survives_cancelled_reentry_and_preserves_guest_state() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    let engine = wasmtime::Engine::new(&config).unwrap();
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
    let initial = 1_000_000;
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_fuel(initial).unwrap();
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let charged = Arc::new(AtomicU64::new(0));
    store.call_hook_async(BoundaryMeter {
        remaining: Arc::new(AtomicU64::new(store.get_fuel().unwrap())),
        charged: charged.clone(),
        throttle: throttle.clone(),
    });
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    assert_eq!(run.call_async(&mut store, ()).await.unwrap(), 1);
    let observed = charged.load(Ordering::Relaxed);
    assert!(observed >= 160, "bulk work was not observed: {observed}");
    assert_eq!(observed, initial - store.get_fuel().unwrap());
    assert!(!throttle.delay().is_zero());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), run.call_async(&mut store, ()))
            .await
            .is_err()
    );
    assert_eq!(charged.load(Ordering::Relaxed), observed);
    assert!(!throttle.delay().is_zero());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), run.call_async(&mut store, ()))
            .await
            .unwrap()
            .unwrap(),
        2,
        "cancelled reentry must not execute or reset guest globals"
    );
    assert_eq!(
        charged.load(Ordering::Relaxed),
        initial - store.get_fuel().unwrap()
    );
}

#[tokio::test]
async fn compute_loop_reports_fuel_at_epoch_and_retains_debt_after_cancellation() {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true).epoch_interruption(true);
    let engine = wasmtime::Engine::new(&config).unwrap();
    let module = wasmtime::Module::new(
        &engine,
        r#"(module (func (export "run") (loop $spin (br $spin))))"#,
    )
    .unwrap();
    let mut store = wasmtime::Store::new(&engine, ());
    let initial = u64::MAX;
    store.set_fuel(initial).unwrap();
    store.fuel_async_yield_interval(Some(32)).unwrap();
    store.set_epoch_deadline(1);
    let meter = BoundaryMeter {
        remaining: Arc::new(AtomicU64::new(initial)),
        charged: Arc::new(AtomicU64::new(0)),
        throttle: throttle.clone(),
    };
    store.call_hook_async(meter.clone());
    let epoch_meter = meter.clone();
    store.epoch_deadline_callback(move |context| {
        epoch_meter.observe(context.get_fuel()?)?;
        let throttle = epoch_meter.throttle.clone();
        Ok(wasmtime::UpdateDeadline::YieldCustom(
            1,
            Box::pin(async move { throttle.wait().await }),
        ))
    });
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
    let result =
        tokio::time::timeout(Duration::from_millis(100), run.call_async(&mut store, ())).await;
    clock.abort();
    let _ = clock.await;
    assert!(result.is_err());
    // Sample after the cancelled future releases its Store borrow as well.
    meter.observe(store.get_fuel().unwrap()).unwrap();
    assert!(meter.charged.load(Ordering::Relaxed) > 100);
    assert_eq!(
        meter.charged.load(Ordering::Relaxed),
        initial - store.get_fuel().unwrap()
    );
    assert!(!throttle.delay().is_zero());
}
