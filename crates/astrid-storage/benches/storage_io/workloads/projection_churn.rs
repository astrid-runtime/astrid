//! Unlogged public-store comparison: live catalog work overlaps UID retirement.
//! Each live content/KV write has verified readback. Fixed work counts prevent
//! faster purge from changing offered work.
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::{
    ContentName, KvQuotaResolver, RuntimePrincipalStore, ScopedKvStore, StateOwner,
    open_runtime_principal_store,
};

use super::checkpoint_churn::phase_cpu::PhaseTimer;
use super::{Config, Report, reset_benchmark_home};
use crate::BenchResult;

// Workload sizes, not product limits. Each live write changes one of 64 names.
const LIVE_FILES: usize = 64;
const LIVE_WRITES: usize = 128;
const PAYLOAD_BYTES: usize = 256;

pub(super) async fn run(config: &Config, root: &Path, report: &mut Report) -> BenchResult<()> {
    let owners = config
        .projection_churn_owners
        .ok_or("missing churn owner count")?
        .get();
    let operations = owners
        .checked_add(LIVE_WRITES.strict_mul(2))
        .ok_or("benchmark operation count overflow")?;
    let path = root.join("projection-churn-home");
    let mut elapsed = Vec::new();
    let mut writes = Vec::new();
    let mut purges = Vec::new();
    for sample in 0..config.samples {
        let mut phase = PhaseTimer::start(sample)?;
        reset_benchmark_home(&path)?;
        let home = AstridHome::from_path(path.clone());
        home.ensure()?;
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store(&home, Arc::clone(&quota)).await?;
        let retiring = prepare(&store, owners).await?;
        phase.mark("projection_churn_setup", report)?;
        let measured = concurrent_churn(&store, &retiring)?;
        elapsed.push(measured.0);
        writes.push(measured.1);
        purges.push(measured.2);
        phase.mark("projection_churn_live_and_retire", report)?;
        store.kv().close().await?;
        drop(store);
        phase.mark("projection_churn_close", report)?;
        let reopened = open_runtime_principal_store(&home, quota).await?;
        for uid in &retiring {
            if reopened.purge_principal_kv(*uid)? {
                return Err("retired KV reappeared on reopen".into());
            }
            if reopened
                .content()
                .read(&StateOwner::Principal(*uid), &ContentName::new("retained")?)?
                != Some(vec![0x5a; PAYLOAD_BYTES])
            {
                return Err("retired non-KV content changed".into());
            }
        }
        for index in 0..LIVE_FILES {
            let name = ContentName::new(format!("live/{index}"))?;
            let expected = vec![
                u8::try_from(LIVE_WRITES.strict_sub(LIVE_FILES).strict_add(index))?;
                PAYLOAD_BYTES
            ];
            if reopened.content().read(&StateOwner::System, &name)? != Some(expected) {
                return Err("live content readback mismatch".into());
            }
        }
        let live = ScopedKvStore::new(reopened.kv(), "system:projection-churn")?;
        if live.get("live").await?
            != Some(vec![
                u8::try_from(LIVE_WRITES.strict_sub(1))?;
                PAYLOAD_BYTES
            ])
        {
            return Err("live KV readback mismatch".into());
        }
        reopened.kv().close().await?;
        phase.mark("projection_churn_verified_reopen", report)?;
    }
    report.record_operations("projection_churn_combined", operations, elapsed);
    report.record_operations(
        "projection_churn_live_writes",
        LIVE_WRITES.strict_mul(2),
        writes,
    );
    report.record_operations("projection_churn_uid_purges", owners, purges);
    Ok(())
}

async fn prepare(store: &RuntimePrincipalStore, owners: usize) -> BenchResult<Vec<PrincipalUid>> {
    let content = store.content();
    for index in 0..LIVE_FILES {
        content.put(
            &StateOwner::System,
            &ContentName::new(format!("live/{index}"))?,
            &[0xff; PAYLOAD_BYTES],
        )?;
    }
    let mut retiring = Vec::with_capacity(owners);
    for index in 0..owners {
        let alias = format!("retiring-{index}");
        let uid = PrincipalUid::from_bytes(*blake3::hash(alias.as_bytes()).as_bytes());
        store
            .principal_directory()
            .register(PrincipalId::new(&alias)?, uid)?;
        store
            .kv()
            .set(
                &format!("{alias}:capsule:projection-churn"),
                "key",
                vec![0x33; PAYLOAD_BYTES],
            )
            .await?;
        content.put(
            &StateOwner::Principal(uid),
            &ContentName::new("retained")?,
            &[0x5a; PAYLOAD_BYTES],
        )?;
        retiring.push(uid);
    }
    Ok(retiring)
}

fn concurrent_churn(
    store: &RuntimePrincipalStore,
    retiring: &[PrincipalUid],
) -> BenchResult<(Duration, Duration, Duration)> {
    let barrier = Barrier::new(3);
    let live_kv = ScopedKvStore::new(store.kv(), "system:projection-churn")?;
    let runtime = tokio::runtime::Handle::try_current()?;
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| -> BenchResult<Duration> {
            let content = store.content();
            barrier.wait();
            let started = Instant::now();
            for index in 0..LIVE_WRITES {
                let name = ContentName::new(format!("live/{}", index % LIVE_FILES))?;
                let value = vec![u8::try_from(index)?; PAYLOAD_BYTES];
                content.put(&StateOwner::System, &name, &value)?;
                if content.read(&StateOwner::System, &name)? != Some(value.clone()) {
                    return Err("concurrent live readback mismatch".into());
                }
                runtime.block_on(async {
                    live_kv.set("live", value.clone()).await?;
                    if live_kv.get("live").await? != Some(value) {
                        return Err("concurrent live KV readback mismatch".into());
                    }
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                })?;
            }
            Ok(started.elapsed())
        });
        let purger = scope.spawn(|| -> BenchResult<Duration> {
            barrier.wait();
            let started = Instant::now();
            for uid in retiring {
                if !store.purge_principal_kv(*uid)? {
                    return Err("fixture UID had no KV to purge".into());
                }
            }
            Ok(started.elapsed())
        });
        let started = Instant::now();
        barrier.wait();
        let foreground_elapsed = writer.join().map_err(|_| "live writer panicked")??;
        let cleanup_elapsed = purger.join().map_err(|_| "purge worker panicked")??;
        Ok((started.elapsed(), foreground_elapsed, cleanup_elapsed))
    })
}
