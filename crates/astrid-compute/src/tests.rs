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

fn growing_worker() -> WorkerArtifact {
    artifact(
        "growing",
        r#"(module
            (memory (import "astrid_compute" "memory") 1 2 shared)
            (func (export "astrid_compute_abi_version") (result i32)
                i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                i32.const 1
                memory.grow
                drop
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

fn artifact_with_asset(asset_bytes: &[u8]) -> (tempfile::TempDir, WorkerArtifact) {
    artifact_with_worker_and_asset(
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func (export "astrid_compute_abi_version") (result i32) i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32) i32.const 0))"#,
        asset_bytes,
    )
}

fn artifact_with_worker_and_asset(
    wat_source: &str,
    asset_bytes: &[u8],
) -> (tempfile::TempDir, WorkerArtifact) {
    let root = tempfile::tempdir().expect("temp capsule root");
    let assets = root.path().join("assets");
    std::fs::create_dir(&assets).expect("asset directory created");
    let worker = artifact("asset-worker", wat_source);
    std::fs::write(assets.join("worker.wasm"), worker.bytes.as_ref()).expect("worker written");
    std::fs::write(assets.join("system.img"), asset_bytes).expect("asset written");
    let asset_hash = format!("blake3:{}", blake3::hash(asset_bytes).to_hex());
    let artifact = WorkerArtifact::from_capsule_path_with_assets(
        "asset-worker",
        root.path(),
        Path::new("assets/worker.wasm"),
        worker.digest(),
        &[WorkerAssetSpec {
            id: "system".to_owned(),
            relative_path: PathBuf::from("assets/system.img"),
            expected_hash: asset_hash,
        }],
    )
    .expect("asset-bearing artifact loads");
    (root, artifact)
}

fn asset_host_store(
    artifact: &WorkerArtifact,
    job_active: bool,
) -> (
    Store<WorkerStoreState>,
    Linker<WorkerStoreState>,
    SharedMemory,
) {
    let mut config = Config::new();
    config
        .wasm_threads(true)
        .shared_memory(true)
        .consume_fuel(true);
    let engine = Engine::new(&config).expect("test engine starts");
    let memory =
        SharedMemory::new(&engine, MemoryType::shared(1, 1)).expect("test shared memory allocates");
    let mut store = Store::new(
        &engine,
        WorkerStoreState {
            cancel: Arc::new(AtomicBool::new(false)),
            group_closed: Arc::new(AtomicBool::new(false)),
            memory: memory.clone(),
            assets: Arc::clone(&artifact.assets),
            job_active,
        },
    );
    store.set_fuel(1_000_000).expect("test fuel seeds");
    let mut linker = Linker::new(&engine);
    link_asset_imports(&mut linker).expect("asset imports link");
    (store, linker, memory)
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
fn immutable_asset_host_calls_are_bounded_metered_and_phase_gated() {
    let asset_bytes = b"0123456789abcdef";
    let (_root, artifact) = artifact_with_asset(asset_bytes);
    assert_eq!(artifact.asset_count(), 1);
    assert_eq!(artifact.asset_bytes(), 16);
    assert_eq!(artifact.asset_id(0), Some("system"));
    assert_eq!(
        artifact.asset_digest(0),
        Some(format!("blake3:{}", blake3::hash(asset_bytes).to_hex()).as_str())
    );

    let (mut store, linker, memory) = asset_host_store(&artifact, true);
    let count = linker
        .get(&mut store, "astrid_compute", "asset_count")
        .expect("count is linked")
        .into_func()
        .expect("count is a function")
        .typed::<(), i32>(&store)
        .expect("count signature matches");
    let size = linker
        .get(&mut store, "astrid_compute", "asset_size")
        .expect("size is linked")
        .into_func()
        .expect("size is a function")
        .typed::<i32, i64>(&store)
        .expect("size signature matches");
    let read = linker
        .get(&mut store, "astrid_compute", "asset_read")
        .expect("read is linked")
        .into_func()
        .expect("read is a function")
        .typed::<(i32, i64, i64, i64), i32>(&store)
        .expect("read signature matches");

    assert_eq!(count.call(&mut store, ()).expect("count returns"), 1);
    assert_eq!(size.call(&mut store, 0).expect("size returns"), 16);
    assert_eq!(
        size.call(&mut store, -1).expect("bad size returns"),
        i64::from(ASSET_ERR_INDEX)
    );

    let before = store.get_fuel().expect("fuel reads");
    assert_eq!(
        read.call(&mut store, (0, 4, 128, 6))
            .expect("valid read returns"),
        ASSET_OK
    );
    let consumed = before.saturating_sub(store.get_fuel().expect("fuel reads"));
    assert_eq!(consumed, ASSET_READ_BASE_FUEL + 6);
    assert_eq!(
        atomic_read_bytes(&memory, 128, 6).expect("copied bytes read"),
        b"456789"
    );

    assert_eq!(
        read.call(&mut store, (-1, 0, 128, 1))
            .expect("bad index returns"),
        ASSET_ERR_INDEX
    );
    assert_eq!(
        read.call(&mut store, (0, -1, 128, 1))
            .expect("negative source returns"),
        ASSET_ERR_RANGE
    );
    assert_eq!(
        read.call(&mut store, (0, 15, 128, 2))
            .expect("source overflow returns"),
        ASSET_ERR_RANGE
    );
    assert_eq!(
        read.call(&mut store, (0, 0, -1, 1))
            .expect("negative destination returns"),
        ASSET_ERR_RANGE
    );
    assert_eq!(
        read.call(&mut store, (0, 0, 128, -1))
            .expect("negative length returns"),
        ASSET_ERR_RANGE
    );
    assert_eq!(
        read.call(
            &mut store,
            (0, 0, 128, i64::try_from(MAX_ASSET_READ_BYTES + 1).unwrap())
        )
        .expect("oversized length returns"),
        ASSET_ERR_LENGTH
    );
    assert_eq!(
        read.call(
            &mut store,
            (0, 0, i64::try_from(WASM_PAGE_BYTES).unwrap(), 1)
        )
        .expect("destination overflow returns"),
        ASSET_ERR_RANGE
    );

    store.set_fuel(ASSET_READ_BASE_FUEL).expect("low fuel sets");
    assert_eq!(
        read.call(&mut store, (0, 0, 128, 1))
            .expect("fuel denial returns"),
        ASSET_ERR_FUEL
    );
    assert_eq!(
        store.get_fuel().expect("fuel remains"),
        ASSET_READ_BASE_FUEL
    );

    store.data_mut().job_active = false;
    store.set_fuel(1_000_000).expect("fuel resets");
    assert_eq!(
        read.call(&mut store, (0, 0, 128, 1))
            .expect("phase denial returns"),
        ASSET_ERR_PHASE
    );
}

#[test]
fn scheduled_worker_reads_verified_asset_into_shared_memory() {
    let (_root, artifact) = artifact_with_worker_and_asset(
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func $read (import "astrid_compute" "asset_read")
                (param i32 i64 i64 i64) (result i32))
            (func (export "astrid_compute_abi_version") (result i32) i32.const 1)
            (func (export "astrid_compute_run")
                (param $worker i32) (param $destination i64)
                (param $length i64) (param $asset_offset i64) (result i32)
                i32.const 0
                local.get $asset_offset
                local.get $destination
                local.get $length
                call $read))"#,
        b"0123456789abcdef",
    );
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &artifact,
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("asset worker opens");
    let result = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 6,
            tag: 4,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("asset job queues")
        .join()
        .expect("asset job completes");
    assert_eq!(result.worker_status, ASSET_OK);
    assert!(result.fuel_consumed >= ASSET_READ_BASE_FUEL + 6);
    assert_eq!(
        group.read(ABI_HEADER_BYTES, 6).expect("asset bytes read"),
        b"456789"
    );
}

#[test]
fn worker_start_function_cannot_read_assets_outside_principal_accounting() {
    let (_root, artifact) = artifact_with_worker_and_asset(
        r#"(module
            (memory (import "astrid_compute" "memory") 1 32 shared)
            (func $read (import "astrid_compute" "asset_read")
                (param i32 i64 i64 i64) (result i32))
            (global $startup_status (mut i32) (i32.const 0))
            (func $start
                i32.const 0
                i64.const 0
                i64.const 128
                i64.const 1
                call $read
                global.set $startup_status)
            (start $start)
            (func (export "astrid_compute_abi_version") (result i32) i32.const 1)
            (func (export "astrid_compute_run")
                (param i32 i64 i64 i64) (result i32)
                global.get $startup_status))"#,
        b"secret",
    );
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &artifact,
            request(ExecutionMode::Deterministic, Parallelism::Auto),
        )
        .expect("phase-gated worker opens");
    let result = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 0,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("status job queues")
        .join()
        .expect("status job completes");
    assert_eq!(result.worker_status, ASSET_ERR_PHASE);
    assert_eq!(
        group.read(128, 1).expect("destination reads"),
        [0],
        "startup must not materialize asset bytes"
    );
}

#[test]
fn malformed_and_duplicate_asset_imports_fail_closed() {
    let malformed = [
        r#"(func (import "astrid_compute" "asset_count") (result i64))"#,
        r#"(func (import "astrid_compute" "asset_size") (param i64) (result i64))"#,
        r#"(func (import "astrid_compute" "asset_read") (param i32 i64 i64) (result i32))"#,
        r#"(global (import "astrid_compute" "asset_count") i32)"#,
        r#"(func (import "astrid_compute" "unknown") (result i32))"#,
        r#"(func $one (import "astrid_compute" "asset_count") (result i32))
            (func $two (import "astrid_compute" "asset_count") (result i32))"#,
    ];
    let runtime = ComputeRuntime::new(ComputeLedger::default(), ComputeLimits::default())
        .expect("runtime starts");
    for import in malformed {
        let worker = artifact(
            "malformed-asset-import",
            &format!(
                r#"(module
                    (memory (import "astrid_compute" "memory") 1 32 shared)
                    {import}
                    (func (export "astrid_compute_abi_version") (result i32) i32.const 1)
                    (func (export "astrid_compute_run")
                        (param i32 i64 i64 i64) (result i32) i32.const 0))"#
            ),
        );
        let error = runtime
            .open_group(
                &principal("alice"),
                &worker,
                request(ExecutionMode::Deterministic, Parallelism::Auto),
            )
            .expect_err("malformed import is rejected");
        assert!(matches!(error, ComputeError::WorkerInvalid(_)));
    }
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
fn principal_policy_intersects_operator_compute_limits() {
    let runtime = ComputeRuntime::new(
        ComputeLedger::default(),
        ComputeLimits {
            max_workers_per_principal: Some(4),
            max_memory_bytes_per_principal: Some(4 * WASM_PAGE_BYTES),
            max_job_fuel: Some(2_000_000),
        },
    )
    .expect("runtime starts");
    let principal_limits = PrincipalComputeLimits {
        max_workers: Some(1),
        max_memory_bytes: Some(WASM_PAGE_BYTES),
        max_job_fuel: Some(1_000_000),
        max_fuel_per_sec: Some(1_000_000),
    };

    assert!(matches!(
        runtime.open_group_with_limits(
            &principal("alice"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
            principal_limits,
        ),
        Err(ComputeError::Quota)
    ));
    assert!(matches!(
        runtime.open_group_with_limits(
            &principal("alice"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Parallel, Parallelism::Exact(2))
            },
            principal_limits,
        ),
        Err(ComputeError::Quota)
    ));

    let group = runtime
        .open_group_with_limits(
            &principal("alice"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
            principal_limits,
        )
        .expect("intersection admits an in-policy group");
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
}

#[test]
fn worker_fuel_joins_the_shared_principal_account() {
    let fuel_ledger = FuelLedger::default();
    let alice = principal("alice");
    let runtime = ComputeRuntime::new_accounted(
        ComputeLedger::default(),
        ComputeLimits::default(),
        fuel_ledger.clone(),
        FuelRateLimiter::default(),
    )
    .expect("runtime starts");
    let group = runtime
        .open_group_with_limits(
            &alice,
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
            PrincipalComputeLimits {
                max_fuel_per_sec: Some(u64::MAX),
                ..PrincipalComputeLimits::default()
            },
        )
        .expect("group opens");
    let result = group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("job queues")
        .join()
        .expect("job completes");

    assert!(result.fuel_consumed > 0);
    assert_eq!(fuel_ledger.total(&alice), result.fuel_consumed);
}

#[test]
fn worker_cpu_rate_denies_the_next_job_for_the_same_principal() {
    let runtime = ComputeRuntime::new_accounted(
        ComputeLedger::default(),
        ComputeLimits::default(),
        FuelLedger::default(),
        FuelRateLimiter::default(),
    )
    .expect("runtime starts");
    let group = runtime
        .open_group_with_limits(
            &principal("alice"),
            &basic_worker(),
            request(ExecutionMode::Deterministic, Parallelism::Auto),
            PrincipalComputeLimits {
                max_fuel_per_sec: Some(1),
                ..PrincipalComputeLimits::default()
            },
        )
        .expect("group opens");
    group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("first job is admitted")
        .join()
        .expect("first job completes");

    assert!(matches!(
        group.submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 4,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        }),
        Err(ComputeError::Quota)
    ));
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
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Parallel, Parallelism::Exact(2))
            },
        )
        .expect("first capsule reserves both workers");
    assert!(matches!(
        runtime_b.open_group(
            &alice,
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
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
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
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
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("alice reserves one");
    let bob = runtime
        .open_group(
            &principal("bob"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("bob independently reserves one");
    assert_eq!(alice.parallelism(), 1);
    assert_eq!(bob.parallelism(), 1);
}

#[test]
fn host_pool_caps_all_principals_together() {
    let ledger = ComputeLedger::default();
    let runtime = ComputeRuntime::new_accounted_with_host_limits(
        ledger.clone(),
        ComputeLimits::default(),
        ComputeHostLimits {
            max_workers: Some(2),
            max_memory_bytes: Some(2 * WASM_PAGE_BYTES),
        },
        FuelLedger::default(),
        FuelRateLimiter::default(),
    )
    .expect("runtime starts");
    let alice = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("Alice reserves half the host pool");
    let bob = runtime
        .open_group(
            &principal("bob"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("Bob reserves the other half");
    assert_eq!(
        ledger.total_usage(),
        PrincipalComputeUsage {
            workers: 2,
            memory_bytes: 2 * WASM_PAGE_BYTES,
        }
    );
    assert!(matches!(
        runtime.open_group(
            &principal("carol"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        ),
        Err(ComputeError::Quota)
    ));
    drop(alice);
    let carol = runtime
        .open_group(
            &principal("carol"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 1,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("released global capacity is reusable");
    assert_eq!(carol.parallelism(), 1);
    drop((bob, carol));
    assert_eq!(ledger.total_usage(), PrincipalComputeUsage::default());
}

#[test]
fn zero_maximum_memory_resolves_to_current_effective_capacity() {
    let ledger = ComputeLedger::default();
    let runtime = ComputeRuntime::new_accounted_with_host_limits(
        ledger.clone(),
        ComputeLimits {
            max_memory_bytes_per_principal: Some(8 * WASM_PAGE_BYTES),
            ..ComputeLimits::default()
        },
        ComputeHostLimits {
            max_workers: None,
            max_memory_bytes: Some(3 * WASM_PAGE_BYTES),
        },
        FuelLedger::default(),
        FuelRateLimiter::default(),
    )
    .expect("runtime starts");
    let group = runtime
        .open_group(
            &principal("alice"),
            &basic_worker(),
            GroupRequest {
                maximum_memory_pages: 0,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("auto memory is admitted");

    assert_eq!(group.maximum_memory_pages(), 3);
    assert_eq!(ledger.total_usage().memory_bytes, 3 * WASM_PAGE_BYTES);
}

#[test]
fn maximum_memory_is_reserved_before_worker_direct_growth() {
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
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
    assert_eq!(group.grow(1).expect("one page admitted"), 1);
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
    assert!(matches!(group.grow(1), Err(ComputeError::WorkerFailed(_))));
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
}

#[test]
fn worker_direct_growth_is_pre_reserved_and_observed_after_the_job() {
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
            &growing_worker(),
            GroupRequest {
                maximum_memory_pages: 2,
                ..request(ExecutionMode::Deterministic, Parallelism::Auto)
            },
        )
        .expect("maximum is admitted before execution");
    assert_eq!(group.memory_pages(), 1);
    assert_eq!(ledger.usage(&alice).memory_bytes, 2 * WASM_PAGE_BYTES);
    group
        .submit(WorkDescriptor {
            offset: ABI_HEADER_BYTES,
            length: 0,
            tag: 0,
            worker_index: None,
            fuel: Some(1_000_000),
        })
        .expect("growth job queues")
        .join()
        .expect("growth job completes");
    assert_eq!(group.memory_pages(), 2);
    assert_eq!(group.accounting().memory_bytes_current, 2 * WASM_PAGE_BYTES);
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

#[test]
fn worker_assets_reject_untrusted_specs_at_runtime() {
    let root = tempfile::tempdir().expect("temp root");
    let assets = root.path().join("assets");
    std::fs::create_dir(&assets).expect("assets directory");
    let worker = basic_worker();
    std::fs::write(assets.join("worker.wasm"), worker.bytes.as_ref()).expect("worker writes");
    std::fs::write(assets.join("system.img"), b"system").expect("asset writes");
    std::fs::write(assets.join("empty.img"), []).expect("empty asset writes");
    let system_hash = format!("blake3:{}", blake3::hash(b"system").to_hex());
    let valid = WorkerAssetSpec {
        id: "system".to_owned(),
        relative_path: PathBuf::from("assets/system.img"),
        expected_hash: system_hash,
    };
    let load = |specs: &[WorkerAssetSpec]| {
        WorkerArtifact::from_capsule_path_with_assets(
            "worker",
            root.path(),
            Path::new("assets/worker.wasm"),
            worker.digest(),
            specs,
        )
    };

    let mut invalid_id = valid.clone();
    invalid_id.id = "SYSTEM".to_owned();
    assert!(matches!(
        load(&[invalid_id]),
        Err(ComputeError::WorkerInvalid(_))
    ));

    let mut bad_hash = valid.clone();
    bad_hash.expected_hash = format!("blake3:{}", "0".repeat(64));
    assert!(matches!(
        load(&[bad_hash]),
        Err(ComputeError::WorkerInvalid(_))
    ));

    let mut traversal = valid.clone();
    traversal.relative_path = PathBuf::from("assets/../outside.img");
    assert!(matches!(
        load(&[traversal]),
        Err(ComputeError::WorkerInvalid(_))
    ));

    let mut empty = valid.clone();
    empty.relative_path = PathBuf::from("assets/empty.img");
    empty.expected_hash = format!("blake3:{}", blake3::hash(&[]).to_hex());
    assert!(matches!(
        load(&[empty]),
        Err(ComputeError::WorkerInvalid(_))
    ));

    assert!(matches!(
        load(&[valid.clone(), valid.clone()]),
        Err(ComputeError::WorkerInvalid(_))
    ));

    let too_many = (0..=MAX_WORKER_ASSETS)
        .map(|index| WorkerAssetSpec {
            id: format!("asset-{index}"),
            ..valid.clone()
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        load(&too_many),
        Err(ComputeError::WorkerInvalid(_))
    ));
}

#[cfg(unix)]
#[test]
fn worker_assets_reject_symlinked_files_at_runtime() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temp root");
    let assets = root.path().join("assets");
    std::fs::create_dir(&assets).expect("assets directory");
    let worker = basic_worker();
    std::fs::write(assets.join("worker.wasm"), worker.bytes.as_ref()).expect("worker writes");
    let outside = tempfile::NamedTempFile::new().expect("outside file");
    std::fs::write(outside.path(), b"outside").expect("outside bytes write");
    symlink(outside.path(), assets.join("system.img")).expect("asset symlink creates");
    let spec = WorkerAssetSpec {
        id: "system".to_owned(),
        relative_path: PathBuf::from("assets/system.img"),
        expected_hash: format!("blake3:{}", blake3::hash(b"outside").to_hex()),
    };

    assert!(matches!(
        WorkerArtifact::from_capsule_path_with_assets(
            "worker",
            root.path(),
            Path::new("assets/worker.wasm"),
            worker.digest(),
            &[spec],
        ),
        Err(ComputeError::WorkerInvalid(_))
    ));
}
