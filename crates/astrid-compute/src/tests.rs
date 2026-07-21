use super::*;

fn artifact(id: &str, wat_source: &str) -> WorkerArtifact {
    let bytes = wat::parse_str(wat_source).expect("test WAT parses");
    let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    WorkerArtifact::from_bytes(id, bytes, &digest).expect("test worker hash matches")
}

fn basic_worker() -> WorkerArtifact {
    artifact(
        "basic",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param $worker i32) (param $offset i64) (param $length i64) (param $tag i64)
                (result i32)
                local.get $offset
                i32.wrap_i64
                i32.const 1
                i32.atomic.rmw.add)
        )"#,
    )
}

fn barrier_worker() -> WorkerArtifact {
    artifact(
        "barrier",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param $worker i32) (param $offset i64) (param $length i64) (param $tag i64)
                (result i32)
                (local $addr i32)
                (local $old i32)
                local.get $offset
                i32.wrap_i64
                local.set $addr
                local.get $addr
                i32.const 1
                i32.atomic.rmw.add
                local.set $old
                local.get $old
                i32.const 1
                i32.eq
                if
                    local.get $addr
                    i32.const 4
                    i32.add
                    i32.const 1
                    i32.atomic.store
                end
                block $released
                    loop $wait
                        local.get $addr
                        i32.const 4
                        i32.add
                        i32.atomic.load
                        br_if $released
                        br $wait
                    end
                end
                local.get $worker)
        )"#,
    )
}

fn infinite_worker() -> WorkerArtifact {
    artifact(
        "infinite",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                (loop $spin br $spin)
                i32.const 0)
        )"#,
    )
}

fn trapping_worker() -> WorkerArtifact {
    artifact(
        "trapping",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                block $released
                    loop $wait
                        i32.const 68
                        i32.atomic.load
                        br_if $released
                        br $wait
                    end
                end
                unreachable)
        )"#,
    )
}

fn expensive_start_worker() -> WorkerArtifact {
    artifact(
        "expensive-start",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func $start
                (local $remaining i32)
                i32.const 2000000
                local.set $remaining
                loop $initialize
                    local.get $remaining
                    i32.const 1
                    i32.sub
                    local.tee $remaining
                    br_if $initialize
                end)
            (start $start)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                i32.const 0))"#,
    )
}

fn infinite_start_worker() -> WorkerArtifact {
    artifact(
        "infinite-start",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func $start (loop $spin br $spin))
            (start $start)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                i32.const 0))"#,
    )
}

fn request(mode: ExecutionMode, parallelism: Parallelism) -> GroupRequest {
    GroupRequest {
        mode,
        parallelism,
        initial_memory_pages: 1,
        maximum_memory_pages: 32,
    }
}

fn principal(name: &str) -> PrincipalId {
    PrincipalId::new(name).expect("valid test principal")
}

#[test]
fn deterministic_jobs_share_memory_and_preserve_queue_order() {
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("group opens");
    assert_eq!(group.parallelism(), 1);
    let descriptor = WorkDescriptor {
        offset: ABI_HEADER_BYTES,
        length: 4,
        tag: 0,
        worker_index: None,
        fuel: Some(1_000_000),
    };
    let first = group.submit(descriptor).expect("first queues");
    let second = group.submit(descriptor).expect("second queues");
    assert_eq!(first.join().expect("first completes").worker_status, 0);
    assert_eq!(second.join().expect("second completes").worker_status, 1);
    assert_eq!(
        group.read(ABI_HEADER_BYTES, 4).expect("memory reads"),
        2_u32.to_le_bytes()
    );
}

#[test]
fn worker_startup_has_no_hidden_one_million_fuel_ceiling() {
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &expensive_start_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("bounded but expensive worker initialization succeeds");
    let result = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 0,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("job queues")
        .join()
        .expect("job completes");
    assert_eq!(result.worker_status, 0);
}

#[test]
fn non_terminating_worker_startup_is_forcibly_interrupted() {
    let runtime = ComputeRuntime::new_with_worker_start_timeout(
        ComputeLedger::default(),
        ComputeLimits::default(),
        Duration::from_millis(100),
    )
    .expect("runtime starts");
    let started = Instant::now();
    let error = runtime
        .open_group(
            &principal("alice"),
            &infinite_start_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect_err("infinite start is rejected");
    assert!(matches!(error, ComputeError::WorkerInvalid(_)));
    assert!(error.to_string().contains("worker startup exceeded"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn two_targeted_workers_execute_concurrently_over_one_memory() {
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &barrier_worker(),
            request(ExecutionMode::Parallel, Parallelism::Exact(2)),
        )
        .expect("two-worker group opens");
    let descriptor = |worker_index| WorkDescriptor {
        offset: ABI_HEADER_BYTES,
        length: 8,
        tag: 0,
        worker_index: Some(worker_index),
        fuel: Some(100_000_000),
    };
    let first = group.submit(descriptor(0)).expect("worker zero queues");
    let second = group.submit(descriptor(1)).expect("worker one queues");
    assert_eq!(
        first
            .join()
            .expect("worker zero passes barrier")
            .worker_status,
        0
    );
    assert_eq!(
        second
            .join()
            .expect("worker one passes barrier")
            .worker_status,
        1
    );
    let bytes = group
        .read(ABI_HEADER_BYTES + 4, 4)
        .expect("release flag reads");
    assert_eq!(bytes, 1_u32.to_le_bytes());
}

#[test]
fn cancelling_non_cooperative_worker_interrupts_store() {
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &infinite_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("group opens");
    let job = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 0,
            tag: 0,
            worker_index: None,
            fuel: Some(u64::MAX),
        })
        .expect("job queues");
    let deadline = Instant::now() + Duration::from_secs(1);
    while job.state() == JobState::Queued && Instant::now() < deadline {
        std::thread::yield_now();
    }
    job.cancel();
    assert_eq!(
        job.join_timeout(Duration::from_secs(1)),
        Some(Err(ComputeError::Cancelled))
    );
}

#[test]
fn worker_trap_closes_group_and_cancels_queued_work() {
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &trapping_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("group opens");
    let descriptor = WorkDescriptor {
        offset: ABI_HEADER_BYTES,
        length: 0,
        tag: 0,
        worker_index: None,
        fuel: Some(1_000_000),
    };
    let failing = group.submit(descriptor).expect("first job queues");
    let queued = group.submit(descriptor).expect("second job queues");
    group
        .write(ABI_HEADER_BYTES + 4, &1_u32.to_le_bytes())
        .expect("release trap worker");

    assert!(matches!(failing.join(), Err(ComputeError::WorkerFailed(_))));
    assert_eq!(queued.join(), Err(ComputeError::Cancelled));
    assert!(group.is_closed());
    assert!(matches!(
        group.submit(descriptor),
        Err(ComputeError::Closed)
    ));
}

#[test]
fn operator_job_fuel_is_a_ceiling_and_none_uses_it() {
    let limits = ComputeLimits {
        max_job_fuel: Some(1_000_000),
        ..ComputeLimits::default()
    };
    let runtime = ComputeRuntime::new(ComputeLedger::default(), limits).expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("group opens");

    assert!(matches!(
        group.submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_001),
        }),
        Err(ComputeError::Quota)
    ));

    let job = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: None,
        })
        .expect("policy-default job queues");
    assert_eq!(job.join().expect("job completes").worker_status, 0);
}

#[test]
fn ledger_aggregates_across_runtimes_and_releases_on_drop() {
    let ledger = ComputeLedger::default();
    let limits = ComputeLimits {
        max_workers_per_principal: Some(2),
        max_memory_bytes_per_principal: Some(2 * WASM_PAGE_BYTES),
        max_job_fuel: None,
    };
    let runtime_a = ComputeRuntime::new(ledger.clone(), limits).expect("runtime A starts");
    let runtime_b = ComputeRuntime::new(ledger.clone(), limits).expect("runtime B starts");
    let alice = principal("alice");
    let first = runtime_a
        .open_group(
            &alice,
            &basic_worker(),
            request(ExecutionMode::Parallel, Parallelism::Exact(2)),
        )
        .expect("first capsule reserves both workers");
    assert!(matches!(
        runtime_b.open_group(
            &alice,
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        ),
        Err(ComputeError::Quota)
    ));
    assert_eq!(ledger.usage(&alice).workers, 2);
    drop(first);
    assert_eq!(ledger.usage(&alice), PrincipalComputeUsage::default());
    let second = runtime_b
        .open_group(
            &alice,
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("released reservation is reusable");
    assert_eq!(second.parallelism(), 1);
}

#[test]
fn principals_do_not_compete_for_each_others_reservation() {
    let ledger = ComputeLedger::default();
    let limits = ComputeLimits {
        max_workers_per_principal: Some(1),
        max_memory_bytes_per_principal: Some(WASM_PAGE_BYTES),
        ..ComputeLimits::default()
    };
    let runtime = ComputeRuntime::new(ledger.clone(), limits).expect("runtime starts");
    let alice = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("alice reserves one");
    let bob = runtime
        .open_group(
            &principal("bob"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("bob independently reserves one");
    assert_eq!(alice.parallelism(), 1);
    assert_eq!(bob.parallelism(), 1);
}

#[test]
fn memory_growth_is_aggregate_and_rolls_back_on_engine_failure() {
    let ledger = ComputeLedger::default();
    let limits = ComputeLimits {
        max_memory_bytes_per_principal: Some(2 * WASM_PAGE_BYTES),
        ..ComputeLimits::default()
    };
    let runtime = ComputeRuntime::new(ledger.clone(), limits).expect("runtime starts");
    let alice = principal("alice");
    let group = runtime
        .open_group(
            &alice,
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("group opens");
    assert_eq!(group.grow(1).expect("one page admitted"), 1);
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
    assert_eq!(group.grow(1), Err(ComputeError::Quota));
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
}

#[test]
fn invalid_hash_imports_and_descriptor_ranges_fail_closed() {
    let bytes = wat::parse_str(
        r#"(module
            (memory (import "evil" "memory") 1 2 shared)
            (func (export "astrid_compute_abi_version") (result i32) i32.const 1)
            (func (export "astrid_compute_run") (param i32 i64 i64 i64) (result i32) i32.const 0))"#,
    )
    .expect("WAT parses");
    assert!(matches!(
        WorkerArtifact::from_bytes("bad", bytes.clone(), "blake3:00"),
        Err(ComputeError::WorkerInvalid(_))
    ));
    let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    let bad_import = WorkerArtifact::from_bytes("bad", bytes, &digest).expect("hash matches");
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    assert!(matches!(
        runtime.open_group(
            &principal("alice"),
            &bad_import,
            request(ExecutionMode::Deterministic, Parallelism::Auto)
        ),
        Err(ComputeError::WorkerInvalid(_))
    ));

    let group = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("valid group opens");
    assert!(matches!(
        group.submit(WorkDescriptor {
            offset: 0,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: None,
        }),
        Err(ComputeError::InvalidInput(_))
    ));
    assert!(matches!(
        group.submit(WorkDescriptor {
            offset: u64::MAX - 1,
            length: 8,
            tag: 0,
            worker_index: None,
            fuel: None,
        }),
        Err(ComputeError::InvalidInput(_))
    ));
}

#[cfg(unix)]
#[test]
fn worker_paths_reject_symlinks_and_escape() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temp root");
    let outside = tempfile::NamedTempFile::new().expect("outside file");
    symlink(outside.path(), root.path().join("worker.wasm")).expect("symlink created");
    assert!(matches!(
        WorkerArtifact::from_capsule_path(
            "worker",
            root.path(),
            Path::new("worker.wasm"),
            "blake3:00"
        ),
        Err(ComputeError::WorkerInvalid(_))
    ));
    assert!(matches!(
        WorkerArtifact::from_capsule_path(
            "worker",
            root.path(),
            Path::new("../worker.wasm"),
            "blake3:00"
        ),
        Err(ComputeError::WorkerInvalid(_))
    ));
}
