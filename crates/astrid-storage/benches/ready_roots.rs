//! Isolated cached-root lookup and retained-handle close benchmark.
//! Usage: `cargo bench -p astrid-storage --bench ready_roots -- 5000000 1024`.
//! Counts select fixed benchmark work, never product limits. No allocation logging.
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use astrid_storage::Blake3ObjectIdentityV1;
use astrid_storage::engine::{
    DurableEngine, KvProjectionEngine, PrincipalCodec, RecoveryLimits, RootTransaction,
};
use astrid_storage::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceLabel, RootState,
};

type BenchResult<T> = Result<T, Box<dyn std::error::Error>>;
type Engine = DurableEngine<String, Blake3ObjectIdentityV1, Utf8Codec>;

#[derive(Clone, Copy)]
struct Utf8Codec;
impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, owner: &String) -> Vec<u8> {
        owner.as_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

#[cfg(unix)]
fn cpu_ns() -> BenchResult<Option<u64>> {
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
fn cpu_ns() -> BenchResult<Option<u64>> {
    Ok(None)
}

fn cpu_delta(before: Option<u64>) -> BenchResult<Option<u64>> {
    match (before, cpu_ns()?) {
        (Some(before), Some(after)) => {
            Ok(Some(after.checked_sub(before).ok_or("CPU went backwards")?))
        },
        _ => Ok(None),
    }
}

fn seed(
    engine: &Engine,
    owner: &str,
    objects: NonZeroUsize,
) -> BenchResult<(RootState, Vec<ObjectId>)> {
    let mut records = Vec::new();
    let mut references = Vec::new();
    let mut ids = Vec::new();
    for index in 0..objects.get() {
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            u64::try_from(index)?.to_le_bytes().to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )?;
        let id = engine.identify(&record);
        references.push(ObjectReference::owns(
            ReferenceLabel::new(format!("item-{index:020}").into_bytes()),
            id,
        ));
        ids.push(id);
        records.push((id, record));
    }
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        Vec::new(),
        references,
        0,
        ObjectClass::Metadata,
    )?;
    let id = engine.identify(&commit);
    records.push((id, commit));
    let root = engine
        .commit(RootTransaction::new(owner.to_owned(), None, id, records))?
        .root();
    Ok((root, ids))
}

fn count(arguments: &mut impl Iterator<Item = String>, default: &str) -> BenchResult<NonZeroUsize> {
    Ok(arguments
        .next()
        .unwrap_or_else(|| default.to_owned())
        .parse()?)
}

fn main() -> BenchResult<()> {
    let mut arguments = std::env::args()
        .skip(1)
        .filter(|argument| argument != "--bench");
    let lookups = count(&mut arguments, "5000000")?;
    let objects = count(&mut arguments, "1024")?;
    if arguments.next().is_some() {
        return Err("expected lookup and object counts".into());
    }
    let directory = tempfile::tempdir()?;
    let engine = Arc::new(Engine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        Utf8Codec,
        RecoveryLimits::process_addressable(),
    )?);
    let owner = "benchmark".to_owned();
    let (expected, ids) = seed(&engine, &owner, objects)?;
    let retained = Arc::clone(&engine);
    let query_cpu = cpu_ns()?;
    let query = Instant::now();
    for _ in 0..lookups.get() {
        let ready = black_box(engine.current_kv_root_if_ready(black_box(&owner)))
            .ok_or("live root unexpectedly unavailable")?;
        if ready.get() != Some(expected) {
            return Err("live root changed".into());
        }
    }
    let query_seconds = query.elapsed().as_secs_f64();
    let query_cpu_nanoseconds = cpu_delta(query_cpu)?;
    let close_cpu = cpu_ns()?;
    let close = Instant::now();
    engine.close()?;
    let close_seconds = close.elapsed().as_secs_f64();
    let close_cpu_nanoseconds = cpu_delta(close_cpu)?;
    if retained.current_kv_root_if_ready(&owner).is_some() {
        return Err("closed root stayed ready".into());
    }
    retained.close()?;
    let reopened = Engine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        Utf8Codec,
        RecoveryLimits::process_addressable(),
    )?;
    if reopened.root(&owner)? != Some(expected) {
        return Err("reopened root changed".into());
    }
    for (index, id) in ids.iter().enumerate() {
        let record = reopened.object(*id)?.ok_or("acknowledged object missing")?;
        if record.canonical_bytes() != u64::try_from(index)?.to_le_bytes() {
            return Err("acknowledged object changed".into());
        }
    }
    reopened.close()?;
    println!(
        "{}",
        serde_json::json!({"lookups": lookups.get(), "objects": objects.get(),
        "query_seconds": query_seconds, "query_cpu_nanoseconds": query_cpu_nanoseconds,
        "close_seconds": close_seconds, "close_cpu_nanoseconds": close_cpu_nanoseconds,
        "retained_handle": true, "verified_reopen_all_objects": true})
    );
    Ok(())
}
