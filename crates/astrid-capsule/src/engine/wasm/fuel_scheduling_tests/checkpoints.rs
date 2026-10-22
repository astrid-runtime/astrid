//! Test-only prototype. No production compilation path uses this transform.

use wasm_encoder::reencode::{Reencode, ReencodeComponent};

struct Checkpoints;

impl Reencode for Checkpoints {
    type Error = std::convert::Infallible;

    fn parse_function_body(
        &mut self,
        code: &mut wasm_encoder::CodeSection,
        body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), wasm_encoder::reencode::Error<Self::Error>> {
        let mut function = self.new_function_with_parsed_locals(&body)?;
        let mut reader = body.get_operators_reader()?;
        while !reader.eof() {
            // The closed empty loop changes neither original branch depths nor
            // operand values. Wasmtime inserts a fuel check at its header.
            function.instruction(&wasm_encoder::Instruction::Loop(
                wasm_encoder::BlockType::Empty,
            ));
            function.instruction(&wasm_encoder::Instruction::End);
            function.instruction(&self.parse_instruction(&mut reader)?);
        }
        code.function(&function);
        Ok(())
    }
}

impl ReencodeComponent for Checkpoints {}

fn component_with_checkpoints(bytes: &[u8]) -> Vec<u8> {
    let mut output = wasm_encoder::Component::new();
    Checkpoints
        .parse_component(&mut output, wasmparser::Parser::new(0), bytes)
        .unwrap();
    output.finish()
}

#[tokio::test]
async fn transformed_component_preserves_start_branches_calls_and_state() {
    let original = wat::parse_str(
        r#"
        (component
          (core module $m
            (global $state (mut i32) (i32.const 0))
            (func $start i32.const 7 global.set $state)
            (start $start)
            (func $increment (result i32)
              global.get $state i32.const 1 i32.add global.set $state
              global.get $state)
            (func (export "run") (param $n i32) (result i32)
              (block $done
                (loop $again
                  local.get $n i32.eqz br_if $done
                  call $increment drop
                  local.get $n i32.const 1 i32.sub local.set $n
                  br $again))
              global.get $state))
          (core instance $i (instantiate $m))
          (func (export "run") (param "n" u32) (result u32)
            (canon lift (core func $i "run"))))
    "#,
    )
    .unwrap();
    let transformed = component_with_checkpoints(&original);
    assert_ne!(original, transformed);
    let engine = super::super::build_wasmtime_engine().unwrap();
    for bytes in [&original, &transformed] {
        let component = wasmtime::component::Component::from_binary(&engine, bytes).unwrap();
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_epoch_deadline(u64::MAX / 2);
        store.set_fuel(1_000_000).unwrap();
        store.fuel_async_yield_interval(Some(10)).unwrap();
        let instance = wasmtime::component::Linker::new(&engine)
            .instantiate_async(&mut store, &component)
            .await
            .unwrap();
        let run = instance
            .get_typed_func::<(u32,), (u32,)>(&mut store, "run")
            .unwrap();
        assert_eq!(run.call_async(&mut store, (30,)).await.unwrap(), (37,));
        assert_eq!(run.call_async(&mut store, (5,)).await.unwrap(), (42,));
    }
}

#[tokio::test]
async fn transformed_component_start_is_subject_to_fuel_checks() {
    let mut wat = String::from("(component (core module $m (func $start (local $x i32)");
    for _ in 0..256 {
        wat.push_str("local.get $x i32.const 1 i32.add local.set $x ");
    }
    wat.push_str(") (start $start)) (core instance (instantiate $m)))");
    let original = wat::parse_str(wat).unwrap();
    let transformed = component_with_checkpoints(&original);
    let engine = super::super::build_wasmtime_engine().unwrap();
    for (bytes, should_trap) in [(&original, false), (&transformed, true)] {
        let component = wasmtime::component::Component::from_binary(&engine, bytes).unwrap();
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_epoch_deadline(u64::MAX / 2);
        store.set_fuel(100).unwrap();
        let result = wasmtime::component::Linker::new(&engine)
            .instantiate_async(&mut store, &component)
            .await;
        if should_trap {
            assert_eq!(
                result.unwrap_err().downcast_ref::<wasmtime::Trap>(),
                Some(&wasmtime::Trap::OutOfFuel)
            );
        } else {
            assert!(result.is_ok(), "unmodified start reproduces the overshoot");
        }
    }
}

#[tokio::test]
async fn epoch_callback_fuel_sample_lags_guest_execution() {
    use std::future::Future;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    let mut wat = String::from("(module (func (export \"run\") (result i32) (local $x i32)");
    for _ in 0..256 {
        wat.push_str("local.get $x i32.const 1 i32.add local.set $x ");
    }
    wat.push_str("local.get $x))");
    let original = wat::parse_str(wat).unwrap();
    let mut transformed = wasm_encoder::Module::new();
    Checkpoints
        .parse_core_module(&mut transformed, wasmparser::Parser::new(0), &original)
        .unwrap();
    let engine = super::super::build_wasmtime_engine().unwrap();
    let module = wasmtime::Module::from_binary(&engine, &transformed.finish()).unwrap();
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_fuel(1_000_000).unwrap();
    store.set_epoch_deadline(u64::MAX / 2);
    let instance = wasmtime::Instance::new_async(&mut store, &module, &[])
        .await
        .unwrap();
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap();
    let initial = store.get_fuel().unwrap();
    let observed = Arc::new(AtomicU64::new(initial));
    let sample = Arc::clone(&observed);
    // Attempt to observe fuel at every checkpoint without modifying it. This
    // deliberately characterizes why these observations are insufficient for
    // exact per-poll settlement: the backend keeps unflushed fuel in registers.
    store.set_epoch_deadline(0);
    store.epoch_deadline_callback(move |context| {
        sample.store(context.get_fuel()?, Ordering::Relaxed);
        Ok(wasmtime::UpdateDeadline::Continue(0))
    });
    let interval = 10;
    store.fuel_async_yield_interval(Some(interval)).unwrap();
    let mut max_burst = 0;
    let mut polls = 0;
    let result = {
        let mut call = std::pin::pin!(run.call_async(&mut store, ()));
        std::future::poll_fn(|cx| {
            let before = observed.load(Ordering::Relaxed);
            let result = call.as_mut().poll(cx);
            max_burst = max_burst.max(before - observed.load(Ordering::Relaxed));
            polls += 1;
            result
        })
        .await
        .unwrap()
    };
    assert_eq!(result, 256);
    assert!(polls > 50);
    let unobserved = observed.load(Ordering::Relaxed) - store.get_fuel().unwrap();
    assert!(
        unobserved > 1,
        "revisit sampler limitation: tail={unobserved}"
    );
    eprintln!(
        "non-exact epoch sampler: tail={unobserved}, observed_burst={max_burst}, polls={polls}"
    );
}
