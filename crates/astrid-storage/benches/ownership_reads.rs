//! Matched public ownership readers, normal allocator, no allocation logging.
//! `cargo bench -p astrid-storage --bench ownership_reads -- alias 1000 1000 1`
//! Count is calls per worker. `cold` includes store creation, one alias read,
//! and drop. `mutate` exercises unchanged fresh-read/CAS with a warmed reader.
//! For `contended`, count is the writer window in milliseconds. Optional fifth
//! argument sets each reader's offered period in microseconds (zero = saturated).
#![deny(unsafe_code)]

use astrid_core::{
    FleetGenesis, FleetIdentity, FleetRole, PrincipalId, PrincipalOwnership, PrincipalUid,
    UserGenesis, UserIdentity,
};
use astrid_storage::ownership::OWNERSHIP_NAMESPACE;
use astrid_storage::{KvStore, MemoryKvStore, OwnershipStore, PrincipalDirectory};
use chrono::{TimeZone as _, Utc};
use std::{error::Error, hint::black_box, num::NonZeroUsize, sync::Arc, time::Instant};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Alias,
    Derive,
    Owned,
    Cold,
    Mutate,
    Contended,
}

struct Args {
    name: String,
    mode: Mode,
    rows: usize,
    calls: usize,
    workers: usize,
    read_period: std::time::Duration,
}
impl Args {
    fn parse() -> Result<Self> {
        let values = std::env::args()
            .skip(1)
            .filter(|s| s != "--bench")
            .collect::<Vec<_>>();
        let values = if values.is_empty() {
            vec!["alias".into(), "1000".into(), "1000".into(), "1".into()]
        } else {
            values
        };
        if !(4..=5).contains(&values.len()) {
            return Err(
                "usage: ownership_reads <alias|derive|owned|cold|mutate|contended> <rows> <calls> <workers> [reader_period_us]"
                    .into(),
            );
        }
        let mode = match values[0].as_str() {
            "alias" => Mode::Alias,
            "derive" => Mode::Derive,
            "owned" => Mode::Owned,
            "cold" => Mode::Cold,
            "mutate" => Mode::Mutate,
            "contended" => Mode::Contended,
            _ => return Err("unknown ownership workload".into()),
        };
        let rows = values[1].parse()?;
        if matches!(mode, Mode::Derive | Mode::Mutate | Mode::Contended) && rows == 0 {
            return Err("derive, mutate and contended require a populated graph".into());
        }
        Ok(Self {
            name: values[0].clone(),
            mode,
            rows,
            calls: values[2].parse::<NonZeroUsize>()?.get(),
            workers: values[3].parse::<NonZeroUsize>()?.get(),
            read_period: std::time::Duration::from_micros(
                values
                    .get(4)
                    .map(|v| v.parse::<u64>())
                    .transpose()?
                    .unwrap_or(0),
            ),
        })
    }
}

struct Fixture {
    backend: Arc<MemoryKvStore>,
    directory: PrincipalDirectory,
    store: OwnershipStore,
    principal: PrincipalUid,
    alias: PrincipalId,
    user: astrid_core::UserUid,
    fleet: astrid_core::FleetUid,
}
impl Fixture {
    async fn new(rows: usize) -> Result<Self> {
        let backend = Arc::new(MemoryKvStore::new());
        let directory = PrincipalDirectory::default();
        let store = OwnershipStore::new(backend.clone(), directory.clone())?;
        let timestamp = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .ok_or("invalid timestamp")?;
        let user = UserIdentity::from_genesis(UserGenesis::from_parts(
            Uuid::from_u128(1),
            timestamp,
            [1; 32],
        ))?;
        let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            Uuid::from_u128(2),
            timestamp,
            user.uid,
        ))?;
        if rows != 0 {
            store.create_user(user.clone()).await?;
            store.create_fleet(fleet.clone()).await?;
            let mut document = serde_json::to_value(store.load().await?)?;
            let mut assignments = serde_json::Map::new();
            let mut accountable = serde_json::Map::new();
            for index in 0..rows {
                let uid = principal(index)?;
                directory.register(PrincipalId::new(format!("agent-{index}"))?, uid)?;
                let key = serde_json::to_value(uid)?
                    .as_str()
                    .ok_or("UID is not text")?
                    .to_owned();
                assignments.insert(
                    key.clone(),
                    serde_json::to_value(PrincipalOwnership {
                        principal_uid: uid,
                        fleet_uid: fleet.uid,
                        assigned_by: user.uid,
                    })?,
                );
                accountable.insert(key, serde_json::to_value(user.uid)?);
            }
            document["principal_ownership"] = serde_json::Value::Object(assignments);
            document["accountable_users"] = serde_json::Value::Object(accountable);
            // Populate the real persisted grammar once; validation remains in
            // the public reader. Avoid O(N²) fixture-creation CAS work.
            let keys = backend.list_keys(OWNERSHIP_NAMESPACE).await?;
            let [graph_key] = keys.as_slice() else {
                return Err("ownership fixture must have exactly one graph key".into());
            };
            backend
                .set(
                    OWNERSHIP_NAMESPACE,
                    graph_key,
                    serde_json::to_vec(&document)?,
                )
                .await?;
            if store.load().await?.principal_owners().count() != rows {
                return Err("ownership fixture does not contain the requested principals".into());
            }
        }
        Ok(Self {
            backend,
            directory,
            store,
            principal: principal(0)?,
            alias: PrincipalId::new("available-alias")?,
            user: user.uid,
            fleet: fleet.uid,
        })
    }

    async fn operation(&self, mode: Mode) -> Result<()> {
        match mode {
            Mode::Alias | Mode::Contended => {
                self.store
                    .ensure_alias_available(black_box(&self.alias))
                    .await?;
            },
            Mode::Derive => {
                black_box(
                    self.store
                        .capture_derived_ownership(black_box(self.principal))
                        .await?,
                );
            },
            Mode::Owned => {
                black_box(self.store.load().await?);
            },
            Mode::Cold => {
                let store = OwnershipStore::new(self.backend.clone(), self.directory.clone())?;
                store.ensure_alias_available(black_box(&self.alias)).await?;
                black_box(store);
            },
            Mode::Mutate => {
                self.store
                    .set_membership(self.fleet, self.user, FleetRole::Owner, self.user)
                    .await?;
            },
        }
        Ok(())
    }
}

fn principal(index: usize) -> Result<PrincipalUid> {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(
        &u128::try_from(index)?
            .checked_add(1)
            .ok_or("UID overflow")?
            .to_le_bytes(),
    );
    Ok(PrincipalUid::from_bytes(bytes))
}

#[cfg(unix)]
fn cpu_ns() -> Result<Option<u64>> {
    use nix::sys::{
        resource::{UsageWho, getrusage},
        time::TimeValLike as _,
    };
    let usage = getrusage(UsageWho::RUSAGE_SELF)?;
    let micros = usage
        .user_time()
        .num_microseconds()
        .checked_add(usage.system_time().num_microseconds())
        .ok_or("CPU overflow")?;
    Ok(Some(
        u64::try_from(micros)?
            .checked_mul(1000)
            .ok_or("CPU overflow")?,
    ))
}
#[cfg(not(unix))]
fn cpu_ns() -> Result<Option<u64>> {
    Ok(None)
}

/// Rename one stable UID while public ownership readers keep validating it.
/// Latency includes real directory lock admission and both alias-map updates.
async fn contended(fixture: Arc<Fixture>, args: &Args) -> Result<()> {
    use std::sync::{
        Barrier,
        atomic::{AtomicBool, Ordering},
    };
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(
        args.workers.checked_add(1).ok_or("worker count overflow")?,
    ));
    let mut readers = tokio::task::JoinSet::new();
    let before = cpu_ns()?;
    let started = Instant::now();
    for _ in 0..args.workers {
        let (fixture, done, barrier) = (fixture.clone(), done.clone(), barrier.clone());
        let read_period = args.read_period;
        readers.spawn(async move {
            let warmup = fixture.operation(Mode::Alias).await;
            barrier.wait();
            warmup?;
            let mut count = 0_u64;
            let mut next_read = Instant::now();
            while !done.load(Ordering::Acquire) {
                fixture.operation(Mode::Alias).await?;
                count = count.checked_add(1).ok_or("reader count overflow")?;
                if !read_period.is_zero() {
                    next_read = next_read
                        .checked_add(read_period)
                        .ok_or("reader schedule overflow")?;
                    std::thread::sleep(next_read.saturating_duration_since(Instant::now()));
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(count)
        });
    }
    let writer_fixture = fixture.clone();
    let writer_done = done.clone();
    let calls = args.calls;
    let writer = std::thread::spawn(move || {
        let result = directory_writes(&writer_fixture, &barrier, calls);
        writer_done.store(true, Ordering::Release);
        result
    });
    let mut reads = 0_u64;
    while let Some(result) = readers.join_next().await {
        reads = reads.checked_add(result??).ok_or("reader count overflow")?;
    }
    let mut samples = writer.join().map_err(|_| "directory writer panicked")??;
    let wall = started.elapsed();
    let cpu = match (before, cpu_ns()?) {
        (Some(a), Some(b)) => Some(b.checked_sub(a).ok_or("CPU reversed")?),
        _ => None,
    };
    samples.sort_unstable();
    let maximum = samples.last().ok_or("writer window produced no samples")?;
    let percentile = |percent: usize| -> Result<u64> {
        let index = samples
            .len()
            .checked_sub(1)
            .and_then(|last| last.checked_mul(percent))
            .ok_or("percentile index overflow")?
            / 100;
        samples
            .get(index)
            .copied()
            .ok_or_else(|| "percentile index out of range".into())
    };
    println!(
        "{}",
        serde_json::json!({"mode":args.name,"rows":args.rows,
        "writer_window_ms":args.calls,"writer_calls":samples.len(),"workers":args.workers,"reads":reads,
        "reader_period_us":u64::try_from(args.read_period.as_micros())?,
        "cpu_ns":cpu,"wall_ns":u64::try_from(wall.as_nanos())?,
        "writer_p50_ns":percentile(50)?,"writer_p95_ns":percentile(95)?,
        "writer_p99_ns":percentile(99)?,"writer_max_ns":maximum})
    );
    Ok(())
}

fn directory_writes(
    fixture: &Fixture,
    barrier: &std::sync::Barrier,
    calls: usize,
) -> Result<Vec<u64>> {
    let original = PrincipalId::new("agent-0")?;
    let temporary = PrincipalId::new("writer-agent-0")?;
    let window = std::time::Duration::from_millis(u64::try_from(calls)?);
    let mut samples = Vec::new();
    barrier.wait();
    let window_start = Instant::now();
    while window_start.elapsed() < window {
        let index = samples.len();
        let (from, to) = if index % 2 == 0 {
            (&original, &temporary)
        } else {
            (&temporary, &original)
        };
        let started = Instant::now();
        fixture
            .directory
            .rename(fixture.principal, from, to.clone())?;
        samples.push(u64::try_from(started.elapsed().as_nanos())?);
    }
    Ok(samples)
}

fn main() -> Result<()> {
    let args = Args::parse()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let fixture = Arc::new(Fixture::new(args.rows).await?);
        if args.mode == Mode::Contended { return contended(fixture, &args).await; }
        // Warm actual public readers and executor threads outside timing.
        fixture.operation(if args.mode == Mode::Mutate { Mode::Alias } else { args.mode }).await?;
        let cpu_before = cpu_ns()?;
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..args.workers {
            let fixture = Arc::clone(&fixture);
            let mode = args.mode;
            let calls = args.calls;
            tasks.spawn(async move {
                for _ in 0..calls { fixture.operation(mode).await?; }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
        }
        while let Some(result) = tasks.join_next().await { result??; }
        let wall = started.elapsed();
        let cpu = match (cpu_before, cpu_ns()?) { (Some(a), Some(b)) => Some(b.checked_sub(a).ok_or("CPU reversed")?), _ => None };
        println!("{}", serde_json::json!({"mode":args.name,"rows":args.rows,"calls_per_worker":args.calls,"workers":args.workers,"cpu_ns":cpu,"wall_ns":u64::try_from(wall.as_nanos())?}));
        Ok(())
    })
}
