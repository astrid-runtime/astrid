use super::*;
use crate::engine::wasm::test_fixtures;

#[test]
fn engine_policy_preserves_the_explicit_guest_feature_boundary() {
    let engine = build_wasmtime_engine().expect("engine");
    let features = engine.get_wasm_features();

    assert!(!features.contains(wasmtime::WasmFeatures::GC));
    assert!(!features.contains(wasmtime::WasmFeatures::EXCEPTIONS));
    assert!(features.contains(wasmtime::WasmFeatures::COMPONENT_MODEL));
}

#[test]
fn compiled_cache_key_is_bound_to_the_wasmtime_48_abi() {
    assert_eq!(
        CompiledArtifactKey::new("verified"),
        CompiledArtifactKey("astrid-wasmtime48-component-abi-v1:verified".to_owned())
    );
}

#[test]
fn stale_wasmtime_47_cache_entry_is_rejected_and_recompiled() {
    let bytes = wasm_encoder::Component::new().finish();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let stale_key = CompiledArtifactKey(format!("astrid-wasmtime47-component-abi-v1:{hash}"));
    let cache = CompiledWasmCache::default();

    let stale = cache
        .compile_with_key(stale_key.clone(), &bytes)
        .expect("stale generation");
    let current = cache.compile(&hash, &bytes).expect("current generation");

    assert!(!Arc::ptr_eq(&stale, &current));
    let entries = cache
        .entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(entries.contains_key(&stale_key));
    assert!(entries.contains_key(&CompiledArtifactKey::new(&hash)));
}

#[test]
fn identical_verified_bytes_share_only_the_compiled_artifact() {
    let bytes = wasm_encoder::Component::new().finish();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let cache = CompiledWasmCache::default();

    let first = cache.compile(&hash, &bytes).expect("first compilation");
    let second = cache.compile(&hash, &bytes).expect("cached compilation");

    assert!(Arc::ptr_eq(&first, &second));
}

#[tokio::test]
async fn shared_compiled_artifact_never_shares_guest_globals() {
    let bytes = wat::parse_str(
        r#"
            (component
              (core module $state
                (global $value (mut i32) (i32.const 0))
                (func (export "set") (param i32)
                  local.get 0
                  global.set $value)
                (func (export "get") (result i32)
                  global.get $value))
              (core instance $state-instance (instantiate $state))
              (func (export "set") (param "value" s32)
                (canon lift (core func $state-instance "set")))
              (func (export "get") (result s32)
                (canon lift (core func $state-instance "get"))))
            "#,
    )
    .expect("valid stateful component");
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let artifact = CompiledWasmCache::default()
        .compile(&hash, &bytes)
        .expect("compiled artifact");

    let mut alice_store = wasmtime::Store::new(
        &artifact.engine,
        test_fixtures::minimal_host_state(tokio::runtime::Handle::current()),
    );
    let mut bob_store = wasmtime::Store::new(
        &artifact.engine,
        test_fixtures::minimal_host_state(tokio::runtime::Handle::current()),
    );
    alice_store.set_fuel(10_000).expect("alice fuel");
    bob_store.set_fuel(10_000).expect("bob fuel");
    alice_store.set_epoch_deadline(u64::MAX);
    bob_store.set_epoch_deadline(u64::MAX);
    let alice = artifact
        .instance_pre
        .instantiate_async(&mut alice_store)
        .await
        .expect("alice instance");
    let bob = artifact
        .instance_pre
        .instantiate_async(&mut bob_store)
        .await
        .expect("bob instance");
    let alice_set = alice
        .get_typed_func::<(i32,), ()>(&mut alice_store, "set")
        .expect("alice set");
    let alice_get = alice
        .get_typed_func::<(), (i32,)>(&mut alice_store, "get")
        .expect("alice get");
    let bob_get = bob
        .get_typed_func::<(), (i32,)>(&mut bob_store, "get")
        .expect("bob get");

    alice_set
        .call_async(&mut alice_store, (0x5a5a_1234,))
        .await
        .expect("set alice global");
    let alice_value = alice_get
        .call_async(&mut alice_store, ())
        .await
        .expect("get alice global");
    let bob_value = bob_get
        .call_async(&mut bob_store, ())
        .await
        .expect("get bob global");

    assert_eq!(alice_value, (0x5a5a_1234,));
    assert_eq!(bob_value, (0,), "Bob must receive a fresh guest instance");
}

#[test]
fn final_runtime_release_removes_compiled_index_entry_immediately() {
    let bytes = wasm_encoder::Component::new().finish();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let cache = CompiledWasmCache::default();
    let first = cache.compile(&hash, &bytes).unwrap();
    let second = cache.compile(&hash, &bytes).unwrap();
    let retired = Arc::downgrade(&first);
    drop(first);
    assert_eq!(cache.entries.lock().unwrap().len(), 1);
    drop(second);
    assert!(retired.upgrade().is_none());
    assert!(cache.entries.lock().unwrap().is_empty());
}

#[test]
fn stale_cleanup_cannot_remove_recompiled_generation() {
    let bytes = wasm_encoder::Component::new().finish();
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let cache = CompiledWasmCache::default();
    let old = cache.compile(&hash, &bytes).unwrap();
    let delayed = Registration {
        cache: Arc::downgrade(&cache.entries),
        key: CompiledArtifactKey::new(&hash),
        artifact: Arc::downgrade(&old),
    };
    drop(old);
    let replacement = cache.compile(&hash, &bytes).unwrap();
    drop(delayed);
    let shared = cache.compile(&hash, &bytes).unwrap();
    assert!(Arc::ptr_eq(&replacement, &shared));
    assert_eq!(cache.entries.lock().unwrap().len(), 1);
}

#[test]
fn concurrent_runtime_churn_leaves_no_retired_keys() {
    let bytes = wasm_encoder::Component::new().finish();
    let cache = CompiledWasmCache::default();
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let cache = &cache;
            let bytes = &bytes;
            scope.spawn(move || {
                for generation in 0..16 {
                    let identity = format!("verified-fixture-{worker}-{generation}");
                    let artifact = cache.compile(&identity, bytes).unwrap();
                    let shared = cache.compile(&identity, bytes).unwrap();
                    assert!(Arc::ptr_eq(&artifact, &shared));
                }
            });
        }
    });
    assert!(cache.entries.lock().unwrap().is_empty());
}
