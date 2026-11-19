//! Decoded-cache owner membership cost through the public durable engine.
//!
//! `cargo bench -p astrid-storage --bench cache_membership -- single 128 1000000`
//! No workload arguments runs `single 128 2000000`. Also measure `shared` and
//! `retire`; the latter's count is retirement rounds.
//! Uses native StateOwner/codec, isolated files and the normal allocator. No
//! allocation observation/logging is compiled into this benchmark binary.
#![deny(unsafe_code)]

use std::error::Error;
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

struct Fixture {
    engine: Engine,
    ids: Vec<ObjectId>,
    owners: [StateOwner; 2],
    retire_second: Arc<AtomicBool>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(count: NonZeroUsize, shared: bool) -> BenchResult<Self> {
        let directory = tempfile::tempdir()?;
        let owners = [
            StateOwner::Principal(PrincipalUid::from_bytes([0; 32])),
            StateOwner::Principal(PrincipalUid::from_bytes([1; 32])),
        ];
        let retire_second = Arc::new(AtomicBool::new(false));
        let retired = retire_second.clone();
        let second = owners[1];
        let engine = Engine::open_with_object_cache(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            ObjectCacheConfig::new(
                ObjectCacheController::new(ObjectCacheCapacity::Unbounded),
                Arc::new(move |owner: &StateOwner| {
                    if *owner == second && retired.load(Ordering::Relaxed) {
                        ObjectCacheCapacity::Disabled
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
            if shared {
                require_record(&engine, owners[1], id)?;
            }
            ids.push(id);
        }
        Ok(Self {
            engine,
            ids,
            owners,
            retire_second,
            _directory: directory,
        })
    }

    fn run(&self, mode: Mode, count: NonZeroUsize) -> BenchResult<()> {
        if mode == Mode::Retire {
            for _ in 0..count.get() {
                self.retire_second.store(true, Ordering::Relaxed);
                self.engine.reclaim_object_cache();
                if self.engine.object_cache_principal_charge(&self.owners[1]) != 0 {
                    return Err("retired principal retained a cache charge".into());
                }
                self.retire_second.store(false, Ordering::Relaxed);
                for id in &self.ids {
                    require_record(&self.engine, self.owners[1], *id)?;
                }
            }
        } else {
            for (index, id) in self.ids.iter().cycle().take(count.get()).enumerate() {
                let owner = self.owners[if mode == Mode::Shared { index % 2 } else { 0 }];
                require_record(&self.engine, owner, *id)?;
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
    if args.len() != 3 {
        return Err(
            "usage: cache_membership <single|shared|retire> <objects> <reads|rounds>".into(),
        );
    }
    let mode = match args[0].as_str() {
        "single" => Mode::Single,
        "shared" => Mode::Shared,
        "retire" => Mode::Retire,
        _ => return Err("unknown cache membership workload".into()),
    };
    let objects = args[1].parse::<NonZeroUsize>()?;
    let count = args[2].parse::<NonZeroUsize>()?;
    let fixture = Fixture::new(objects, mode != Mode::Single)?;
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
            "mode": args[0], "objects": objects.get(), "count": count.get(),
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
