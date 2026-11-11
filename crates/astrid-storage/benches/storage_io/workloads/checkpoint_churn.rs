//! Exclusive 256-byte content overwrite profile.
//!
//! Times a fixed number of durable named-content puts, then reports public
//! generation-region census after close. Generation advance is observed, not
//! required: main lacks automatic representation checkpointing.

use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_storage::volume::{AstridVolume, HostedFileVolume};
use astrid_storage::{
    ContentName, KvQuotaResolver, NativePrincipalContentStore, RuntimePrincipalStore, StateOwner,
    open_runtime_principal_store,
};

use super::{Config, Report, benchmark_owner, reset_benchmark_home};
use crate::BenchResult;

const SLOT_COUNT: u64 = 16;
const PAYLOAD_BYTES: usize = 256;
const ANCHOR_PERIOD: u64 = 256;
const GENERATIONS_PREFIX: &str = "representations/generations/";
const METADATA_FILE: &str = "metadata.arena";

pub(super) async fn run(config: &Config, root: &Path, report: &mut Report) -> BenchResult<()> {
    let overwrites = config
        .checkpoint_overwrites
        .ok_or("checkpoint overwrite mode requires --checkpoint-overwrites N")?
        .get();
    let home_path = root.join("astrid-home");
    let owner = benchmark_owner();
    let mut puts = Vec::new();
    let mut loops = Vec::new();
    let mut readbacks = Vec::new();
    let mut generations = Vec::new();
    let mut region_counts = Vec::new();
    let mut metadata_lengths = Vec::new();
    for _ in 0..config.samples {
        reset_benchmark_home(&home_path)?;
        let home = AstridHome::from_path(home_path.clone());
        home.ensure()?;
        let store = open_runtime_store(&home).await?;
        let measured = overwrite_loop(&store, &owner, overwrites)?;
        store.kv().close().await?;
        drop(store);

        let volume = HostedFileVolume::open(home.storage_volume_path())?;
        let (generation, region_count, metadata_bytes) = generation_census(volume.as_ref())?;
        drop(volume);

        let reopened = open_runtime_store(&home).await?;
        readbacks.extend(read_retained_content(
            reopened.content().as_ref(),
            &owner,
            &measured.expected,
        )?);
        reopened.kv().close().await?;
        drop(reopened);

        puts.extend(measured.latencies);
        loops.push(measured.wall);
        generations.push(generation);
        region_counts.push(region_count);
        metadata_lengths.push(metadata_bytes);
    }

    report.record_operations("astrid_checkpoint_overwrite", 1, puts);
    report.record_operations("astrid_checkpoint_overwrite_loop", overwrites, loops);
    report.record_operations("astrid_checkpoint_verified_content_read", 1, readbacks);
    report.record_counts("representations_max_generation", generations)?;
    report.record_counts("representations_generation_region_count", region_counts)?;
    report.record_resource_peak("representations_metadata_logical_bytes", metadata_lengths)?;
    Ok(())
}

async fn open_runtime_store(home: &AstridHome) -> BenchResult<RuntimePrincipalStore> {
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    open_runtime_principal_store(home, quota)
        .await
        .map_err(Into::into)
}

struct OverwriteMeasurements {
    latencies: Vec<Duration>,
    expected: Vec<(ContentName, [u8; PAYLOAD_BYTES])>,
    wall: Duration,
}

fn overwrite_loop(
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    overwrites: usize,
) -> BenchResult<OverwriteMeasurements> {
    let content = store.content();
    let mut latencies = Vec::with_capacity(overwrites);
    let mut expected = Vec::new();
    let mut latest = (0..SLOT_COUNT).map(|_| None).collect::<Vec<_>>();
    let wall_started = Instant::now();
    for sequence in 0..overwrites {
        let sequence = u64::try_from(sequence)?;
        let payload = payload(sequence);
        let name = put_name(sequence)?;
        let started = Instant::now();
        black_box(content.put(owner, &name, &payload)?);
        latencies.push(started.elapsed());
        if sequence.is_multiple_of(ANCHOR_PERIOD) {
            expected.push((name, payload));
        } else {
            latest[usize::try_from(sequence % SLOT_COUNT)?] = Some((name, payload));
        }
    }
    let wall = wall_started.elapsed();
    // Verify both untouched versioned anchors and the latest overwritten slots.
    // Accepting puts without updating existing values must not look fast.
    expected.extend(latest.into_iter().flatten());
    Ok(OverwriteMeasurements {
        latencies,
        expected,
        wall,
    })
}

fn put_name(sequence: u64) -> BenchResult<ContentName> {
    let name = if sequence.is_multiple_of(ANCHOR_PERIOD) {
        format!("checkpoint/anchor/{sequence:016x}")
    } else {
        format!("checkpoint/slot/{:02}", sequence % SLOT_COUNT)
    };
    ContentName::new(name).map_err(Into::into)
}

fn payload(sequence: u64) -> [u8; PAYLOAD_BYTES] {
    let mut bytes = [0_u8; PAYLOAD_BYTES];
    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
    let mixed = sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (index, slot) in bytes[8..].chunks_mut(8).enumerate() {
        let mix = mixed.wrapping_add(u64::try_from(index).expect("payload mix index fits u64"));
        slot.copy_from_slice(&mix.to_le_bytes()[..slot.len()]);
    }
    bytes
}

fn generation_census(volume: &dyn AstridVolume) -> BenchResult<(u64, u64, u64)> {
    let regions = volume.list_regions(GENERATIONS_PREFIX)?;
    if regions.is_empty() {
        return Err("opened store published no representations/generations regions".into());
    }
    let mut max_generation = 0_u64;
    let mut metadata_bytes = 0_u64;
    for region in &regions {
        let Some(suffix) = region.as_str().strip_prefix(GENERATIONS_PREFIX) else {
            return Err(format!("generation region {} escaped its prefix", region.as_str()).into());
        };
        let Some((generation, file)) = suffix.split_once('/') else {
            return Err(format!(
                "generation region {} has no file component",
                region.as_str()
            )
            .into());
        };
        let generation = u64::from_str_radix(generation, 16).map_err(|error| {
            format!("generation region {} is not hex: {error}", region.as_str())
        })?;
        max_generation = max_generation.max(generation);
        if file == METADATA_FILE {
            metadata_bytes = metadata_bytes
                .checked_add(volume.region_len(region)?)
                .ok_or("representation metadata logical length overflow")?;
        }
    }
    Ok((
        max_generation,
        u64::try_from(regions.len())?,
        metadata_bytes,
    ))
}

fn read_retained_content(
    content: &NativePrincipalContentStore,
    owner: &StateOwner,
    expected_content: &[(ContentName, [u8; PAYLOAD_BYTES])],
) -> BenchResult<Vec<Duration>> {
    if expected_content.is_empty() {
        return Err("checkpoint overwrite mode retained no content names".into());
    }
    let mut samples = Vec::with_capacity(expected_content.len());
    for (name, expected) in expected_content {
        let started = Instant::now();
        let actual = content.read(owner, name)?.ok_or_else(|| {
            format!(
                "retained content name {} missing after reopen",
                name.as_str()
            )
        })?;
        let elapsed = started.elapsed();
        if actual.as_slice() != expected.as_slice() {
            return Err(format!(
                "retained content name {} changed after reopen",
                name.as_str()
            )
            .into());
        }
        black_box(actual);
        samples.push(elapsed);
    }
    Ok(samples)
}
