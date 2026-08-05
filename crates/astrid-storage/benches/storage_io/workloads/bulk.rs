//! Bulk-ingest and delta-reingest workloads.

use std::fs::File;
use std::hint::black_box;
use std::io::{Read, Seek, SeekFrom};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_storage::{
    BulkIngestPolicy, ContentChangeCache, ContentIngest, ContentName, NativePrincipalContentStore,
    SourceEpoch, SourceFingerprint, SourceObservation, SourceScopeId, StableSourceId, StateOwner,
};

use super::{Config, Report, benchmark_owner, open_store};
use crate::BenchResult;

pub(super) async fn benchmark_bulk_ingest(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    let parts = config
        .bulk_files
        .min(usize::try_from(config.bytes).unwrap_or(usize::MAX))
        .max(1);
    let worker_count =
        NonZeroUsize::new(config.bulk_workers.min(parts)).ok_or("bulk worker count is zero")?;
    let change_cache_bytes = u64::try_from(parts)
        .map_err(|_| "bulk change-cache budget overflow")?
        .checked_mul(1024)
        .and_then(NonZeroU64::new)
        .ok_or("bulk change-cache budget overflow")?;
    let mut single_worker = Vec::with_capacity(config.samples);
    let mut parallel = Vec::with_capacity(config.samples);
    let mut unchanged = Vec::with_capacity(config.samples);
    let mut one_file_delta = Vec::with_capacity(config.samples);
    let changed_part = parts / 2;
    let delta_bytes = partition_bounds(config.bytes, parts, changed_part)?.1;
    let plan = BulkSamplePlan {
        parts,
        worker_count,
        change_cache_bytes,
        changed_part,
        delta_bytes,
    };
    for sample in 0..config.samples {
        let result = run_bulk_sample(config, root, source, source_digest, sample, plan).await?;
        single_worker.push(result.single_worker);
        parallel.push(result.parallel);
        unchanged.push(result.unchanged);
        one_file_delta.push(result.one_file_delta);
    }
    report.record_bytes(
        "astrid_bulk_publish_single_worker",
        config.bytes,
        single_worker,
    );
    report.record_bytes("astrid_bulk_publish_parallel", config.bytes, parallel);
    report.record_operations("astrid_bulk_reingest_unchanged", 1, unchanged);
    report.record_bytes(
        "astrid_bulk_reingest_one_file_delta",
        delta_bytes,
        one_file_delta,
    );
    report.record_throughput_scaling(
        "bulk_parallel_ingest",
        "astrid_bulk_publish_parallel",
        "astrid_bulk_publish_single_worker",
    )?;
    Ok(())
}

struct BulkSample {
    single_worker: Duration,
    parallel: Duration,
    unchanged: Duration,
    one_file_delta: Duration,
}

#[derive(Clone, Copy)]
struct BulkSamplePlan {
    parts: usize,
    worker_count: NonZeroUsize,
    change_cache_bytes: NonZeroU64,
    changed_part: usize,
    delta_bytes: u64,
}

async fn run_bulk_sample(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    sample: usize,
    plan: BulkSamplePlan,
) -> BenchResult<BulkSample> {
    let single_home = AstridHome::from_path(root.join(format!("bulk-single-{sample}")));
    single_home.ensure()?;
    let single = open_store(&single_home, config.object_cache_bytes).await?;
    let (sources, _) = bulk_sources(source, config.bytes, plan.parts, None)?;
    let started = Instant::now();
    let outcome = single.content().put_streaming_batch_with_policy(
        &benchmark_owner(),
        sources,
        BulkIngestPolicy::new(NonZeroUsize::MIN),
    )?;
    let single_worker = started.elapsed();
    verify_bulk_content(
        single.content().as_ref(),
        &benchmark_owner(),
        &outcome,
        config.bytes,
        config.range_bytes,
        source_digest,
    )?;
    drop(single);

    let parallel_home = AstridHome::from_path(root.join(format!("bulk-parallel-{sample}")));
    parallel_home.ensure()?;
    let parallel_store = open_store(&parallel_home, config.object_cache_bytes).await?;
    let cache = ContentChangeCache::new(plan.change_cache_bytes);
    let (sources, _) = bulk_sources(source, config.bytes, plan.parts, None)?;
    let started = Instant::now();
    let outcome = parallel_store
        .content()
        .put_streaming_batch_with_change_cache(
            &benchmark_owner(),
            sources,
            BulkIngestPolicy::new(plan.worker_count),
            &cache,
        )?;
    let parallel = started.elapsed();
    verify_bulk_content(
        parallel_store.content().as_ref(),
        &benchmark_owner(),
        &outcome,
        config.bytes,
        config.range_bytes,
        source_digest,
    )?;

    let (sources, unchanged_reads) = bulk_sources(source, config.bytes, plan.parts, None)?;
    let started = Instant::now();
    black_box(
        parallel_store
            .content()
            .put_streaming_batch_with_change_cache(
                &benchmark_owner(),
                sources,
                BulkIngestPolicy::new(plan.worker_count),
                &cache,
            )?,
    );
    let unchanged = started.elapsed();
    if unchanged_reads.load(Ordering::SeqCst) != 0 {
        return Err("unchanged bulk re-ingest read source bytes".into());
    }

    let (sources, delta_reads) =
        bulk_sources(source, config.bytes, plan.parts, Some(plan.changed_part))?;
    let started = Instant::now();
    black_box(
        parallel_store
            .content()
            .put_streaming_batch_with_change_cache(
                &benchmark_owner(),
                sources,
                BulkIngestPolicy::new(plan.worker_count),
                &cache,
            )?,
    );
    let one_file_delta = started.elapsed();
    if delta_reads.load(Ordering::SeqCst) != plan.delta_bytes {
        return Err("delta re-ingest observed bytes outside the changed source".into());
    }
    Ok(BulkSample {
        single_worker,
        parallel,
        unchanged,
        one_file_delta,
    })
}

fn bulk_sources(
    source: &Path,
    logical_bytes: u64,
    parts: usize,
    changed_part: Option<usize>,
) -> BenchResult<(Vec<ContentIngest<BulkPartReader>>, Arc<AtomicU64>)> {
    let observed_bytes = Arc::new(AtomicU64::new(0));
    let mut ingests = Vec::with_capacity(parts);
    for index in 0..parts {
        let index_u64 = u64::try_from(index)?;
        let (start, length) = partition_bounds(logical_bytes, parts, index)?;
        let mut file = File::open(source)?;
        file.seek(SeekFrom::Start(start))?;
        let mut stable = [0_u8; 16];
        stable[..8].copy_from_slice(&index_u64.to_le_bytes());
        let fingerprint = SourceFingerprint::new(
            SourceScopeId::new([0x42; 32]),
            PathBuf::from(format!("{}#part-{index}", source.display())),
            length,
            i128::from(changed_part == Some(index)),
            StableSourceId::new(stable),
            SourceEpoch::new([0x24; 32]),
        );
        ingests.push(
            ContentIngest::new(
                ContentName::new(format!("bulk/part-{index:08}.bin"))?,
                BulkPartReader {
                    inner: file.take(length),
                    flip_first_byte: changed_part == Some(index),
                    observed_bytes: Arc::clone(&observed_bytes),
                },
            )
            .with_observation(SourceObservation::trusted(fingerprint)),
        );
    }
    Ok((ingests, observed_bytes))
}

fn partition_bounds(logical_bytes: u64, parts: usize, index: usize) -> BenchResult<(u64, u64)> {
    let parts_u64 = u64::try_from(parts)?;
    let index_u64 = u64::try_from(index)?;
    let start = logical_bytes
        .checked_mul(index_u64)
        .ok_or("bulk partition offset overflow")?
        .checked_div(parts_u64)
        .ok_or("bulk partition divisor is zero")?;
    let end = logical_bytes
        .checked_mul(index_u64.saturating_add(1))
        .ok_or("bulk partition end overflow")?
        .checked_div(parts_u64)
        .ok_or("bulk partition divisor is zero")?;
    let length = end
        .checked_sub(start)
        .ok_or("bulk partition length underflow")?;
    Ok((start, length))
}

struct BulkPartReader {
    inner: std::io::Take<File>,
    flip_first_byte: bool,
    observed_bytes: Arc<AtomicU64>,
}

impl Read for BulkPartReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let length = self.inner.read(output)?;
        if self.flip_first_byte && length != 0 {
            output[0] ^= 0x80;
            self.flip_first_byte = false;
        }
        self.observed_bytes
            .fetch_add(u64::try_from(length).unwrap_or(u64::MAX), Ordering::SeqCst);
        Ok(length)
    }
}

fn verify_bulk_content(
    content: &NativePrincipalContentStore,
    owner: &StateOwner,
    outcome: &astrid_storage::ContentBatchWriteOutcome,
    logical_bytes: u64,
    range_bytes: usize,
    expected: [u8; 32],
) -> BenchResult<()> {
    let mut hasher = blake3::Hasher::new();
    let mut observed = 0_u64;
    for entry in outcome.entries() {
        let length = entry.descriptor().logical_bytes();
        let mut offset = 0_u64;
        while offset < length {
            let remaining = length.saturating_sub(offset);
            let request = remaining.min(u64::try_from(range_bytes)?);
            let bytes = content
                .read_range(owner, entry.name(), offset, request)?
                .ok_or("bulk publication omitted a named entry")?;
            hasher.update(&bytes);
            offset = offset
                .checked_add(request)
                .ok_or("bulk verification offset overflow")?;
            observed = observed
                .checked_add(request)
                .ok_or("bulk verification length overflow")?;
        }
    }
    if observed != logical_bytes || hasher.finalize().as_bytes() != &expected {
        return Err("bulk publication digest mismatch".into());
    }
    Ok(())
}
