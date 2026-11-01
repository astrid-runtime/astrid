//! Constructor, first-use and warm-contention costs of the real runtime registries.
//!
//! Run with `cargo bench -p astrid-capsule --bench registry_overhead -- --rounds 7`.
//! This is a diagnostic, not a CI performance gate. Compare identical commands on
//! a quiet host without allocation logging, preserving the per-round output and
//! executable/source identities. It does not measure whole-daemon startup or RSS.

use std::hash::Hash;
use std::hint::black_box;
use std::sync::{Arc, Barrier, OnceLock};
use std::time::Instant;

use astrid_core::principal::PrincipalId;
use astrid_events::IpcRateLimiter;
use dashmap::DashMap;
use serde_json::json;
use uuid::Uuid;

use astrid_capsule::engine::wasm::host_state::HostState;

// Keep the same benchmark source usable on the eager-map baseline. Both
// adapters inline into the real map operation; the lazy adapter includes the
// initialization check paid by the production access path.
trait RegistryAccess<K, V> {
    fn initialized_map(&self) -> &DashMap<K, V>;
}

impl<K: Eq + Hash, V> RegistryAccess<K, V> for Arc<DashMap<K, V>> {
    fn initialized_map(&self) -> &DashMap<K, V> {
        self
    }
}

impl<K: Eq + Hash, V> RegistryAccess<K, V> for Arc<OnceLock<DashMap<K, V>>> {
    fn initialized_map(&self) -> &DashMap<K, V> {
        self.get_or_init(DashMap::new)
    }
}

struct Options {
    rounds: usize,
    iterations: usize,
    cold_iterations: usize,
}

fn options() -> Options {
    let mut options = Options {
        rounds: 7,
        iterations: 10_000,
        cold_iterations: 1_000,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        // Cargo passes --bench to harness=false executables.
        if arg == "--bench" {
            continue;
        }
        let value = args
            .next()
            .expect("benchmark option requires a positive integer")
            .parse::<usize>()
            .expect("benchmark option must be an integer");
        assert!(value > 0, "benchmark options must be positive");
        match arg.as_str() {
            "--rounds" => options.rounds = value,
            "--iterations" => options.iterations = value,
            "--cold-iterations" => options.cold_iterations = value,
            _ => panic!("unknown benchmark option: {arg}"),
        }
    }
    options
}

fn require_unlogged_environment() {
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        assert!(
            !key.starts_with("Malloc") && key != "DYLD_INSERT_LIBRARIES" && key != "LD_PRELOAD",
            "remove allocation logging/injected libraries before measuring: {key}"
        );
    }
}

fn distribution(samples: &mut [u128]) -> serde_json::Value {
    samples.sort_unstable();
    let rank = |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1];
    json!({
        "n": samples.len(), "min_ns": samples[0],
        "mean_ns": samples.iter().sum::<u128>() as f64 / samples.len() as f64,
        "p50_ns": rank(50), "p95_ns": rank(95), "p99_ns": rank(99),
        "max_ns": samples[samples.len() - 1]
    })
}

fn cold_registries(round: usize, iterations: usize) {
    let principal = PrincipalId::new("registry-benchmark").expect("valid synthetic principal");
    let capsule = Uuid::from_u128(1);
    let mut construction = Vec::with_capacity(iterations);
    let mut first_use = Vec::with_capacity(iterations);
    let mut destruction = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let identities = HostState::new_connection_principals();
        let clients = HostState::new_client_connections();
        let listeners = HostState::new_shared_listeners();
        let limiter = IpcRateLimiter::new();
        construction.push(start.elapsed().as_nanos());

        let start = Instant::now();
        black_box(identities.initialized_map());
        clients.initialized_map().insert(1, principal.clone());
        black_box(listeners.initialized_map());
        limiter
            .check_quota(capsule, &principal, 1, usize::MAX)
            .expect("synthetic first byte fits");
        first_use.push(start.elapsed().as_nanos());

        let start = Instant::now();
        drop(black_box((identities, clients, listeners, limiter)));
        destruction.push(start.elapsed().as_nanos());
    }
    let mut combined = construction
        .iter()
        .zip(&first_use)
        .zip(&destruction)
        .map(|((construction, first_use), destruction)| construction + first_use + destruction)
        .collect::<Vec<_>>();
    println!(
        "{}",
        json!({"case":"construct_first_use_drop", "round":round,
            "construction":distribution(&mut construction),
            "first_use":distribution(&mut first_use),
            "destruction":distribution(&mut destruction),
            "combined_measured_phases":distribution(&mut combined),
            "first_use_scope":"initialize all four maps; one client-map insertion and one quota check"})
    );
}

fn unused_registries(round: usize, iterations: usize) {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        drop(black_box((
            HostState::new_connection_principals(),
            HostState::new_client_connections(),
            HostState::new_shared_listeners(),
            IpcRateLimiter::new(),
        )));
        samples.push(start.elapsed().as_nanos());
    }
    println!(
        "{}",
        json!({"case":"unused_construct_drop", "round":round,
            "duration":distribution(&mut samples)})
    );
}

fn warm_registry(round: usize, workers: usize, iterations: usize) {
    let registry = HostState::new_client_connections();
    black_box(registry.initialized_map());
    let principal = PrincipalId::new("registry-benchmark").expect("valid synthetic principal");
    let ready = Barrier::new(workers + 1);
    let elapsed = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let registry = &registry;
            let principal = &principal;
            let ready = &ready;
            handles.push(scope.spawn(move || {
                let key = u32::try_from(worker).expect("worker count fits stream rep");
                ready.wait();
                for _ in 0..iterations {
                    registry.initialized_map().insert(key, principal.clone());
                    assert_eq!(
                        registry.initialized_map().get(&key).as_deref(),
                        Some(principal)
                    );
                    assert!(registry.initialized_map().remove(&key).is_some());
                }
            }));
        }
        let start = Instant::now();
        ready.wait();
        for handle in handles {
            handle.join().expect("registry worker must pass its oracle");
        }
        start.elapsed()
    });
    assert!(registry.initialized_map().is_empty());
    let logical_iterations = workers * iterations;
    println!(
        "{}",
        json!({"case":"warm_registry_insert_get_remove", "round":round,
            "workers":workers, "iterations_per_worker":iterations,
            "logical_iterations":logical_iterations, "map_operations":logical_iterations * 3,
            "elapsed_ns":elapsed.as_nanos(),
            "iterations_per_second":logical_iterations as f64 / elapsed.as_secs_f64(),
            "scope":"distinct worker stream reps; includes start barrier and completion joins, excludes thread creation"})
    );
}

fn warm_limiter(round: usize, workers: usize, iterations: usize, shared_key: bool) {
    let limiter = IpcRateLimiter::new();
    let capsule = Uuid::from_u128(1);
    let principals = (0..workers)
        .map(|worker| {
            PrincipalId::new(format!(
                "registry-benchmark-{}",
                if shared_key { 0 } else { worker }
            ))
            .expect("valid synthetic principal")
        })
        .collect::<Vec<_>>();
    for principal in &principals {
        limiter
            .check_quota(capsule, principal, 1, usize::MAX)
            .expect("synthetic initialization fits");
    }
    let ready = Barrier::new(workers + 1);
    let elapsed = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for principal in &principals {
            let limiter = &limiter;
            let ready = &ready;
            handles.push(scope.spawn(move || {
                ready.wait();
                for _ in 0..iterations {
                    black_box(limiter.check_quota(capsule, principal, 1, usize::MAX))
                        .expect("synthetic quota cannot exhaust in this run");
                }
            }));
        }
        let start = Instant::now();
        ready.wait();
        for handle in handles {
            handle.join().expect("limiter worker must pass its oracle");
        }
        start.elapsed()
    });
    let checks = workers * iterations;
    println!(
        "{}",
        json!({"case":"warm_limiter", "round":round, "workers":workers,
            "shared_key":shared_key, "checks":checks, "elapsed_ns":elapsed.as_nanos(),
            "checks_per_second":checks as f64 / elapsed.as_secs_f64(),
            "scope":"quota ceiling unchanged; includes start barrier and completion joins, excludes thread creation"})
    );
}

fn main() {
    require_unlogged_environment();
    let options = options();
    println!(
        "{}",
        json!({"benchmark":"registry_overhead", "ci_performance_gate":false,
            "allocation_logging":false, "whole_daemon_performance_accepted":false,
            "rounds":options.rounds, "iterations_per_worker":options.iterations,
            "cold_iterations":options.cold_iterations,
            "available_parallelism":std::thread::available_parallelism().map(usize::from).ok()})
    );
    for round in 0..options.rounds {
        unused_registries(round, options.cold_iterations);
        cold_registries(round, options.cold_iterations);
        for workers in [1, 2, 4, 8, 16] {
            warm_registry(round, workers, options.iterations);
            warm_limiter(round, workers, options.iterations, false);
            warm_limiter(round, workers, options.iterations, true);
        }
    }
}
