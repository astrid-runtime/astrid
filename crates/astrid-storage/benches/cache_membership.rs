//! Decoded-cache owner membership cost through the public durable engine.
//!
//! `cargo bench -p astrid-storage --bench cache_membership -- single 128 1000000`
//! No workload arguments runs `single 128 2000000`. Also measure `shared` and
//! `retire` and `pressure` (half the owner quota); their counts are rounds.
//! The optional fourth
//! argument sets the number of sharing owners (default two), and the fifth
//! sets how many retire together (default one, leaving at least one owner).
//! Uses native StateOwner/codec, isolated files and the normal allocator. No
//! allocation observation/logging is compiled into this benchmark binary.
#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::hint::black_box;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use astrid_core::identity::PrincipalUid;
use astrid_storage::engine::{
    DurableEngine, ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, RecoveryLimits,
};
use astrid_storage::principal_state::{Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV2};
use astrid_storage::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
};

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
type Engine = DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV2>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Single,
    Shared,
    Retire,
    Pressure,
}

struct Fixture {
    engine: Engine,
    ids: Vec<ObjectId>,
    owners: Vec<StateOwner>,
    retiring_owners: usize,
    pressure_active: Arc<AtomicBool>,
    pressure_target: Arc<AtomicU64>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(
        count: NonZeroUsize,
        mode: Mode,
        owner_count: NonZeroUsize,
        retiring_owners: usize,
    ) -> BenchResult<Self> {
        let directory = tempfile::tempdir()?;
        let owners = (0..owner_count.get())
            .map(|index| {
                let mut bytes = [0; 32];
                let encoded = index.to_le_bytes();
                bytes[..encoded.len()].copy_from_slice(&encoded);
                StateOwner::Principal(PrincipalUid::from_bytes(bytes))
            })
            .collect::<Vec<_>>();
        let pressure_active = Arc::new(AtomicBool::new(false));
        let retired = pressure_active.clone();
        let pressure_target = Arc::new(AtomicU64::new(0));
        let target = Arc::clone(&pressure_target);
        let retirement = owners
            .iter()
            .rev()
            .take(retiring_owners)
            .copied()
            .collect::<BTreeSet<_>>();
        let engine = Engine::open_with_object_cache(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            ObjectCacheConfig::new(
                ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
                Arc::new(move |owner: &StateOwner| {
                    if retired.load(Ordering::Relaxed) && retirement.contains(owner) {
                        NonZeroU64::new(target.load(Ordering::Relaxed))
                            .map_or(ObjectCacheCapacity::Disabled, ObjectCacheCapacity::Bounded)
                    } else {
                        ObjectCacheCapacity::Unbounded
                    }
                }),
            ),
        )?;
        let mut ids = Vec::with_capacity(count.get());
        for index in 0..count.get() {
            let record = ObjectRecord::new(
                ObjectKind::Chunk,
                ObjectFormatVersion::V1,
                u64::try_from(index)?.to_le_bytes().to_vec(),
                Vec::new(),
                8,
                ObjectClass::Data,
            )?;
            let id = engine.persist_standalone_object(&record)?.0;
            require_record(&engine, owners[0], id)?;
            if mode != Mode::Single {
                for owner in owners.iter().skip(1) {
                    require_record(&engine, *owner, id)?;
                }
            }
            ids.push(id);
        }
        if mode == Mode::Pressure {
            pressure_target.store(
                engine.object_cache_principal_charge(&owners[0]) / 2,
                Ordering::Relaxed,
            );
        }
        Ok(Self {
            engine,
            ids,
            owners,
            retiring_owners,
            pressure_active,
            pressure_target,
            _directory: directory,
        })
    }

    fn run(&self, mode: Mode, count: NonZeroUsize) -> BenchResult<()> {
        if matches!(mode, Mode::Retire | Mode::Pressure) {
            for _ in 0..count.get() {
                self.pressure_active.store(true, Ordering::Relaxed);
                self.engine.reclaim_object_cache();
                for owner in self.owners.iter().rev().take(self.retiring_owners) {
                    if self.engine.object_cache_principal_charge(owner)
                        > self.pressure_target.load(Ordering::Relaxed)
                    {
                        return Err("principal retained more than its pressure target".into());
                    }
                }
                self.pressure_active.store(false, Ordering::Relaxed);
                for id in &self.ids {
                    for owner in self.owners.iter().rev().take(self.retiring_owners) {
                        require_record(&self.engine, *owner, *id)?;
                    }
                }
            }
        } else {
            let owners = if mode == Mode::Shared {
                &self.owners[..]
            } else {
                &self.owners[..1]
            };
            for (id, owner) in self
                .ids
                .iter()
                .cycle()
                .zip(owners.iter().cycle())
                .take(count.get())
            {
                require_record(&self.engine, *owner, *id)?;
            }
        }
        Ok(())
    }
}

fn require_record(engine: &Engine, owner: StateOwner, id: ObjectId) -> BenchResult<()> {
    if black_box(engine.shared_object_for(&owner, id)?).is_none() {
        return Err("cached record disappeared".into());
    }
    Ok(())
}

#[cfg(unix)]
fn cpu_and_rss() -> BenchResult<(Option<u64>, Option<u64>)> {
    use nix::sys::resource::{UsageWho, getrusage};
    use nix::sys::time::TimeValLike as _;
    let usage = getrusage(UsageWho::RUSAGE_SELF)?;
    let micros = usage
        .user_time()
        .num_microseconds()
        .checked_add(usage.system_time().num_microseconds())
        .ok_or("CPU counter overflow")?;
    let cpu = u64::try_from(micros)?
        .checked_mul(1000)
        .ok_or("CPU counter overflow")?;
    let rss = u64::try_from(usage.max_rss())?;
    let rss = if cfg!(target_os = "macos") {
        Some(rss)
    } else if cfg!(target_os = "linux") {
        Some(rss.checked_mul(1024).ok_or("RSS overflow")?)
    } else {
        None
    };
    Ok((Some(cpu), rss))
}

#[cfg(not(unix))]
fn cpu_and_rss() -> BenchResult<(Option<u64>, Option<u64>)> {
    Ok((None, None))
}

fn main() -> BenchResult<()> {
    let args = std::env::args()
        .skip(1)
        .filter(|argument| argument != "--bench")
        .collect::<Vec<_>>();
    let args = if args.is_empty() {
        vec!["single".to_owned(), "128".to_owned(), "2000000".to_owned()]
    } else {
        args
    };
    if !(3..=5).contains(&args.len()) {
        return Err(
            "usage: cache_membership <single|shared|retire|pressure> <objects> <reads|rounds> [owners] [retiring-owners]"
                .into(),
        );
    }
    let mode = match args[0].as_str() {
        "single" => Mode::Single,
        "shared" => Mode::Shared,
        "retire" => Mode::Retire,
        "pressure" => Mode::Pressure,
        _ => return Err("unknown cache membership workload".into()),
    };
    let objects = args[1].parse::<NonZeroUsize>()?;
    let count = args[2].parse::<NonZeroUsize>()?;
    let owners = args
        .get(3)
        .map_or("2", String::as_str)
        .parse::<NonZeroUsize>()?;
    if owners.get() < 2 {
        return Err("at least two owners required".into());
    }
    let retiring = args
        .get(4)
        .map_or("1", String::as_str)
        .parse::<NonZeroUsize>()?;
    if retiring.get() >= owners.get() {
        return Err("at least one owner must remain".into());
    }
    let fixture = Fixture::new(objects, mode, owners, retiring.get())?;
    let before = fixture.engine.object_cache_stats();
    let (cpu_before, _) = cpu_and_rss()?;
    let started = Instant::now();
    fixture.run(mode, count)?;
    let elapsed = started.elapsed();
    let (cpu_after, rss) = cpu_and_rss()?;
    let cpu = match (cpu_before, cpu_after) {
        (Some(before), Some(after)) => Some(
            after
                .checked_sub(before)
                .ok_or("CPU counter went backwards")?,
        ),
        _ => None,
    };
    let stats = fixture.engine.object_cache_stats();
    if stats.resident_objects != before.resident_objects {
        return Err("cache residency changed during measured hits".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "mode": args[0], "owners": owners.get(), "retiring_owners": retiring.get(), "objects": objects.get(), "count": count.get(),
            "wall_ns": u64::try_from(elapsed.as_nanos())?, "cpu_ns": cpu,
            "process_lifetime_peak_rss_bytes": rss,
            "hits": stats.hits.checked_sub(before.hits).ok_or("hit counter went backwards")?,
            "resident_objects": stats.resident_objects,
            "resident_associations": stats.resident_associations,
            "resident_bytes": stats.resident_bytes,
            "first_charge": fixture.engine.object_cache_principal_charge(&fixture.owners[0]),
            "second_charge": fixture.engine.object_cache_principal_charge(&fixture.owners[1]),
        })
    );
    Ok(())
}
