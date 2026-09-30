use std::sync::Arc;

use super::pool::{CapsuleInstancePool, InstanceBuilder, InstantiationEpochPolicy};
use super::{WasmEngine, build_wasmtime_engine, test_fixtures::minimal_host_state};
use crate::capsule::InterceptResult;
use crate::engine::ExecutionEngine;

// A mutable guest flag stands in for a RefCell borrow or partially built cache.
// Fuel exhaustion must not carry that unfinished mutation into the next call.
const COMPONENT: &str = r#"
(component
  (import "pause" (func $pause))
  (import "expire" (func $expire))
  (core func $pause (canon lower (func $pause)))
  (core func $expire (canon lower (func $expire)))
  (core module $guest
    (import "host" "pause" (func $pause))
    (import "host" "expire" (func $expire))
    (memory (export "memory") 1)
    (global $dirty (mut i32) (i32.const 0))
    (data (i32.const 0) "continue")
    (data (i32.const 16) "deny")
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 256)
    (func (export "hook") (param $action i32) (param i32 i32 i32) (result i32)
      local.get $action i32.load8_u i32.const 102 i32.eq
      if
        i32.const 1 global.set $dirty
        loop $spin br $spin end
      end
      local.get $action i32.load8_u i32.const 120 i32.eq
      if
        i32.const 1 global.set $dirty
        unreachable
      end
      local.get $action i32.load8_u i32.const 112 i32.eq
      if i32.const 1 global.set $dirty call $pause end
      local.get $action i32.load8_u i32.const 109 i32.eq
      if
        i32.const 1 global.set $dirty
        i32.const 1024 memory.grow i32.const -1 i32.eq
        if unreachable end
      end
      local.get $action i32.load8_u i32.const 101 i32.eq
      if
        i32.const 1 global.set $dirty
        call $expire
        loop $spin br $spin end
      end
      i32.const 32
      global.get $dirty
      if (result i32) i32.const 16 else i32.const 0 end
      i32.store
      i32.const 36
      global.get $dirty
      if (result i32) i32.const 4 else i32.const 8 end
      i32.store
      local.get $action i32.load8_u i32.const 115 i32.eq
      if i32.const 1 global.set $dirty end
      i32.const 32))
  (core instance $g (instantiate $guest (with "host" (instance
    (export "pause" (func $pause)) (export "expire" (func $expire))))))
  (type $result (record (field "action" string) (field "data" (option string))))
  (export $public-result "capsule-result" (type $result))
  (func (export "astrid-hook-trigger")
    (param "action" string) (param "payload" (list u8)) (result $public-result)
    (canon lift (core func $g "hook")
      (memory $g "memory") (realloc (func $g "realloc")))))
"#;

async fn engine(max: usize) -> WasmEngine {
    engine_with_pause(max, Arc::new(tokio::sync::Notify::new())).await
}

async fn engine_with_pause(max: usize, entered: Arc<tokio::sync::Notify>) -> WasmEngine {
    let wasm = build_wasmtime_engine().expect("engine");
    let component = wasmtime::component::Component::new(&wasm, COMPONENT).expect("component");
    let mut linker = wasmtime::component::Linker::new(&wasm);
    linker
        .root()
        .func_wrap_async("pause", move |_store, (): ()| {
            let entered = entered.clone();
            Box::new(async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                Ok(())
            })
        })
        .expect("pause import");
    let ticking = wasm.clone();
    linker
        .root()
        .func_wrap("expire", move |_store, (): ()| {
            for _ in 0..100_000 {
                ticking.increment_epoch();
            }
            Ok(())
        })
        .expect("epoch import");
    let handle = tokio::runtime::Handle::current();
    let builder = InstanceBuilder::new(
        wasm.clone(),
        linker.instantiate_pre(&component).expect("preinstantiate"),
        Arc::new(move || minimal_host_state(handle.clone())),
        InstantiationEpochPolicy::Deadline(1_000_000),
        1_000_000,
    );
    let initial = vec![builder.build().await.expect("initial instance")];
    let mut engine = WasmEngine::new(
        toml::from_str("[package]\nname = 'interruption-test'\nversion = '0.0.1'")
            .expect("manifest"),
        std::path::PathBuf::new(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        super::limits::CapsuleRuntimeLimits::default(),
        super::limits::HttpLimits::default(),
    );
    engine.pool = Some(CapsuleInstancePool::new(
        initial,
        max,
        1,
        max != 1,
        builder,
        &tokio_util::sync::CancellationToken::new(),
    ));
    engine.wasmtime_engine = Some(wasm);
    engine
}

#[tokio::test]
async fn fuel_interruption_denies_instead_of_returning_a_skippable_error() {
    let engine = engine(2).await;
    let result = engine.invoke_interceptor("fuel", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Deny { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn fuel_interruption_discards_mutated_guest_state() {
    let engine = engine(2).await;
    let _ = engine.invoke_interceptor("fuel", &[], None).await;
    let result = engine.invoke_interceptor("read", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Continue(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn fixed_size_pool_replaces_a_trapped_instance() {
    let engine = engine(1).await;
    assert!(engine.invoke_interceptor("read", &[], None).await.is_ok());
    let _ = engine.invoke_interceptor("x", &[], None).await;
    let result = engine.invoke_interceptor("read", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Continue(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn successful_calls_keep_the_warm_guest_instance() {
    let engine = engine(2).await;
    let result = engine.invoke_interceptor("set", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Continue(_))),
        "{result:?}"
    );
    let result = engine.invoke_interceptor("read", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Deny { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn epoch_interruption_denies_and_recovers() {
    let engine = engine(2).await;
    let result = engine.invoke_interceptor("epoch", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Deny { .. })),
        "{result:?}"
    );
    let result = engine.invoke_interceptor("read", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Continue(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn guest_trap_denies_instead_of_skipping_the_guard() {
    let engine = engine(2).await;
    for action in ["x", "memory"] {
        let result = engine.invoke_interceptor(action, &[], None).await;
        assert!(
            matches!(result, Ok(InterceptResult::Deny { .. })),
            "{action}: {result:?}"
        );
        let result = engine.invoke_interceptor("read", &[], None).await;
        assert!(
            matches!(result, Ok(InterceptResult::Continue(_))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn cancelled_call_discards_mutated_guest_state() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let engine = engine_with_pause(1, entered.clone()).await;
    {
        let pending = engine.invoke_interceptor("pause", &[], None);
        tokio::pin!(pending);
        tokio::select! {
            () = entered.notified() => {},
            result = &mut pending => panic!("guest must wait: {result:?}"),
        }
    }
    let result = engine.invoke_interceptor("read", &[], None).await;
    assert!(
        matches!(result, Ok(InterceptResult::Continue(_))),
        "{result:?}"
    );
}

struct DispatchCapsule {
    id: crate::capsule::CapsuleId,
    manifest: crate::manifest::CapsuleManifest,
    engine: Option<WasmEngine>,
    completed: Arc<tokio::sync::Notify>,
}

impl DispatchCapsule {
    fn new(name: &str, priority: u32, engine: Option<WasmEngine>) -> Self {
        Self {
            id: crate::capsule::CapsuleId::new(name).expect("capsule id"),
            manifest: toml::from_str(&format!(
                "[package]\nname = '{name}'\nversion = '0.0.1'\n\
                 [subscribe]\n\
                 'test.fuel' = {{ wit = 'opaque', handler = 'fuel', priority = {priority} }}\n\
                 'test.read' = {{ wit = 'opaque', handler = 'read', priority = {priority} }}"
            ))
            .expect("manifest"),
            engine,
            completed: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

#[async_trait::async_trait]
impl crate::capsule::Capsule for DispatchCapsule {
    fn id(&self) -> &crate::capsule::CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &crate::manifest::CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> crate::capsule::CapsuleState {
        crate::capsule::CapsuleState::Ready
    }
    async fn load(
        &mut self,
        _: &crate::context::CapsuleContext,
    ) -> crate::error::CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> crate::error::CapsuleResult<()> {
        Ok(())
    }
    async fn invoke_interceptor(
        &self,
        action: &str,
        _: &[u8],
        caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> crate::error::CapsuleResult<InterceptResult> {
        let result = match &self.engine {
            Some(engine) => engine.invoke_interceptor(action, &[], caller).await,
            None => Ok(InterceptResult::Continue(Vec::new())),
        };
        self.completed.notify_one();
        result
    }
}

#[tokio::test]
async fn fuel_interruption_halts_the_real_dispatcher_chain_then_recovers() {
    use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
    use std::time::Duration;

    let guard = DispatchCapsule::new("guard", 10, Some(engine(2).await));
    let downstream = DispatchCapsule::new("downstream", 100, None);
    let checked = guard.completed.clone();
    let executed = downstream.completed.clone();
    let mut registry = crate::registry::CapsuleRegistry::new();
    registry
        .register(Box::new(guard))
        .expect("guard registered");
    registry
        .register(Box::new(downstream))
        .expect("downstream registered");
    let bus = Arc::new(astrid_events::EventBus::with_capacity(64));
    let dispatcher = crate::dispatcher::EventDispatcher::new(
        Arc::new(tokio::sync::RwLock::new(registry)),
        bus.clone(),
    );
    let task = tokio::spawn(dispatcher.run());
    let publish = |topic| {
        bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw(topic),
                IpcPayload::Custom {
                    data: serde_json::json!({}),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("default".to_owned()),
        })
    };
    publish("test.fuel");
    tokio::time::timeout(Duration::from_secs(10), checked.notified())
        .await
        .expect("guard completed");
    let bypassed = tokio::time::timeout(Duration::from_millis(50), executed.notified())
        .await
        .is_ok();
    if bypassed {
        task.abort();
    }
    assert!(
        !bypassed,
        "a fuel-interrupted guard must not run the downstream handler"
    );

    publish("test.read");
    let recovered = tokio::time::timeout(Duration::from_secs(10), executed.notified()).await;
    task.abort();
    recovered.expect("next valid request must reach the handler through the recovered guard");
}
