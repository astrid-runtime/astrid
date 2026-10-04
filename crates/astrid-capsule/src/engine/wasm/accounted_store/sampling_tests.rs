//! Fuel sampling must pace pure computation without an epoch callback or
//! guest host imports, including component initialization before pool checkout.

use super::*;
use crate::user_cpu::tests::accounting;
use astrid_core::PrincipalId;
use std::time::Duration;

const COMPUTE: &str = r#"
    (func $compute (export "run")
        (local $left i32)
        (local.set $left (i32.const 10000))
        (loop $again
            (local.set $left (i32.sub (local.get $left) (i32.const 1)))
            (br_if $again (local.get $left))))
"#;

#[tokio::test]
async fn fuel_hooks_pace_pure_component_start_without_epoch_callback() {
    assert_pure_compute_is_paced(true).await;
}

#[tokio::test]
async fn fuel_hooks_pace_pure_foreground_call_without_epoch_callback() {
    assert_pure_compute_is_paced(false).await;
}

async fn assert_pure_compute_is_paced(component_start: bool) {
    let accounting = accounting().await;
    let throttle = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let mut raw = Store::new(&engine, ());
    raw.set_fuel(u64::MAX).unwrap();
    raw.set_epoch_deadline(u64::MAX / 2);
    let mut store = AccountedStore::new(raw, Some(throttle)).unwrap();
    let remaining = store.meter.as_ref().unwrap().remaining.clone();
    let result = if component_start {
        let component = wasmtime::component::Component::new(
            &engine,
            format!("(component (core module $m {COMPUTE} (start $compute)) (core instance (instantiate $m)))"),
        )
        .unwrap();
        let linker = wasmtime::component::Linker::<()>::new(&engine);
        tokio::time::timeout(
            Duration::from_millis(100),
            linker.instantiate_async(&mut store, &component),
        )
        .await
        .map(|result| result.map(|_| ()))
    } else {
        let module = wasmtime::Module::new(&engine, format!("(module {COMPUTE})")).unwrap();
        let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
            .await
            .unwrap();
        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .unwrap();
        tokio::time::timeout(Duration::from_millis(100), run.call_async(&mut store, ())).await
    };
    assert!(
        result.is_err(),
        "pure computation escaped the configured rate: {result:?}"
    );
    let observed = u64::MAX - remaining.load(Ordering::Relaxed);
    assert!(observed >= 100, "must actually spend the initial credit");
    assert!(
        observed < 1000,
        "must sample within the guest, not at its return: {observed}"
    );
}
