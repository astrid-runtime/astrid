//! Matched cold `read()` vs sequential `read_range` timings.
//!
//! Measures the authenticated partial-verification retain path used by
//! `AuthenticatedContentReader::refill` without allocation logging and without
//! a product Cargo feature. Select the I/O request size with `--range-bytes`. Cache residency is forced empty outside the timed
//! interval so publish/open warming cannot masquerade as a cold arm.

use std::hint::black_box;
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_storage::{
    ContentName, ObjectCacheCapacity, ObjectCacheStats, RuntimePrincipalStore, StateOwner,
};

use super::{Config, Report, benchmark_owner, open_store, stage_source};
use crate::BenchResult;

const CONTENT_NAME: &str = "large/partial-verification.bin";

#[derive(Clone, Copy)]
enum Arm {
    FullRead,
    WindowedRanges,
}

impl Arm {
    const fn wall_metric(self) -> &'static str {
        match self {
            Self::FullRead => "partial_verification_cold_read",
            Self::WindowedRanges => "partial_verification_cold_windowed_range",
        }
    }

    const fn insertion_metric(self) -> &'static str {
        match self {
            Self::FullRead => "partial_verification_cold_read_projection_insertions",
            Self::WindowedRanges => "partial_verification_cold_windowed_projection_insertions",
        }
    }

    const fn resident_metric(self) -> &'static str {
        match self {
            Self::FullRead => "partial_verification_cold_read_resident_projection_bytes",
            Self::WindowedRanges => "partial_verification_cold_windowed_resident_projection_bytes",
        }
    }
}

struct ArmMeasurement {
    elapsed: Duration,
    projection_insertions_delta: u64,
    resident_projection_bytes_after: u64,
    window_bytes: Option<u64>,
}

/// Run only the partial-verification clone timing workload (ABBA, cold cache).
pub(super) async fn benchmark_partial_verification_clone(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    let budget = config
        .object_cache_bytes
        .ok_or("--partial-verification-clone requires nonzero --object-cache-bytes")?;
    let owner = benchmark_owner();
    let home = AstridHome::from_path(root.join("partial-verification-clone-home"));
    home.ensure()?;

    let store = open_store(&home, Some(budget)).await?;
    let (name, staged, _write, _seal) =
        stage_source(&store, source, &owner, CONTENT_NAME, config.block_bytes)?;
    let published = store.publish_staged(staged).await?;
    let profile_maximum = u64::from(published.descriptor().profile().maximum_bytes());
    black_box(published);
    // Publish admits into a live Bounded cache; force empty residency before
    // timed arms so both sides start identically cold.
    force_cold_cache(&store, budget)?;

    let mut read_wall = Vec::with_capacity(config.samples);
    let mut windowed_wall = Vec::with_capacity(config.samples);
    let mut read_insertions = Vec::with_capacity(config.samples);
    let mut windowed_insertions = Vec::with_capacity(config.samples);
    let mut read_resident = Vec::with_capacity(config.samples);
    let mut windowed_resident = Vec::with_capacity(config.samples);
    let mut window_bytes = None;

    for sample in 0..config.samples {
        // Even: A then B. Odd: B then A. Across pairs this is ABBA.
        let order = if sample % 2 == 0 {
            [Arm::FullRead, Arm::WindowedRanges]
        } else {
            [Arm::WindowedRanges, Arm::FullRead]
        };
        for arm in order {
            force_cold_cache(&store, budget)?;
            let measured = measure_arm(
                &store,
                &owner,
                &name,
                config.bytes,
                config.range_bytes,
                source_digest,
                arm,
            )?;
            if let Some(window) = measured.window_bytes {
                window_bytes.get_or_insert(window);
            }
            match arm {
                Arm::FullRead => {
                    read_wall.push(measured.elapsed);
                    read_insertions.push(measured.projection_insertions_delta);
                    read_resident.push(measured.resident_projection_bytes_after);
                },
                Arm::WindowedRanges => {
                    windowed_wall.push(measured.elapsed);
                    windowed_insertions.push(measured.projection_insertions_delta);
                    windowed_resident.push(measured.resident_projection_bytes_after);
                },
            }
            force_cold_cache(&store, budget)?;
        }
    }
    drop(store);

    report.record_bytes(Arm::FullRead.wall_metric(), config.bytes, read_wall);
    report.record_bytes(
        Arm::WindowedRanges.wall_metric(),
        config.bytes,
        windowed_wall,
    );
    report.record_counts(Arm::FullRead.insertion_metric(), read_insertions)?;
    report.record_counts(Arm::WindowedRanges.insertion_metric(), windowed_insertions)?;
    report.record_resource_peak(Arm::FullRead.resident_metric(), read_resident)?;
    report.record_resource_peak(Arm::WindowedRanges.resident_metric(), windowed_resident)?;
    if let Some(window) = window_bytes {
        report.record_resource_peak("partial_verification_window_request_bytes", vec![window])?;
    }
    report.record_resource_peak(
        "partial_verification_profile_maximum_bytes",
        vec![profile_maximum],
    )?;
    Ok(())
}

fn measure_arm(
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    name: &ContentName,
    total_bytes: u64,
    range_bytes: usize,
    expected: [u8; 32],
    arm: Arm,
) -> BenchResult<ArmMeasurement> {
    match arm {
        Arm::FullRead => measure_full_read(store, owner, name, total_bytes, expected),
        Arm::WindowedRanges => {
            measure_windowed_ranges(store, owner, name, total_bytes, range_bytes, expected)
        },
    }
}

fn measure_full_read(
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    name: &ContentName,
    total_bytes: u64,
    expected: [u8; 32],
) -> BenchResult<ArmMeasurement> {
    let before = store.object_cache_stats();
    let started = Instant::now();
    let handle = store
        .content()
        .open_read(owner, name)?
        .ok_or("published content missing for cold read()")?;
    let bytes = handle.read()?;
    let window = usize::try_from(handle.descriptor().profile().maximum_bytes())?;
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(window) {
        hasher.update(black_box(chunk));
    }
    let digest = *hasher.finalize().as_bytes();
    let length = u64::try_from(bytes.len())?;
    // Keep the full Vec live through black_box, then drop inside the interval.
    drop(black_box(bytes));
    let elapsed = started.elapsed();
    if length != total_bytes {
        return Err("cold read() length mismatch".into());
    }
    if digest != expected {
        return Err("cold read() digest mismatch".into());
    }
    Ok(delta_measurement(
        before,
        store.object_cache_stats(),
        elapsed,
        None,
    ))
}

fn measure_windowed_ranges(
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    name: &ContentName,
    total_bytes: u64,
    range_bytes: usize,
    expected: [u8; 32],
) -> BenchResult<ArmMeasurement> {
    let before = store.object_cache_stats();
    let started = Instant::now();
    let handle = store
        .content()
        .open_read(owner, name)?
        .ok_or("published content missing for cold windowed ranges")?;
    // The benchmark controls request batching independently of chunk format.
    // Hash in the same profile-sized strides as the full-read consumer.
    let digest_stride = usize::try_from(handle.descriptor().profile().maximum_bytes())?;
    let window = u64::try_from(range_bytes)?;
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0_u64;
    while offset < total_bytes {
        let want = total_bytes.strict_sub(offset).min(window);
        let chunk = handle.read_range(offset, want)?;
        if u64::try_from(chunk.len())? != want {
            return Err("cold windowed range length mismatch".into());
        }
        for piece in chunk.chunks(digest_stride) {
            hasher.update(black_box(piece));
        }
        drop(black_box(chunk));
        offset = offset
            .checked_add(want)
            .ok_or("cold windowed range offset overflow")?;
    }
    let digest = *hasher.finalize().as_bytes();
    let length = offset;
    let elapsed = started.elapsed();
    if length != total_bytes {
        return Err("cold windowed consumed length mismatch".into());
    }
    if digest != expected {
        return Err("cold windowed digest mismatch".into());
    }
    Ok(delta_measurement(
        before,
        store.object_cache_stats(),
        elapsed,
        Some(window),
    ))
}

fn delta_measurement(
    before: ObjectCacheStats,
    after: ObjectCacheStats,
    elapsed: Duration,
    window_bytes: Option<u64>,
) -> ArmMeasurement {
    ArmMeasurement {
        elapsed,
        projection_insertions_delta: after
            .projection_insertions
            .strict_sub(before.projection_insertions),
        resident_projection_bytes_after: after.resident_projection_bytes,
        window_bytes,
    }
}

fn force_cold_cache(store: &RuntimePrincipalStore, budget: u64) -> BenchResult<()> {
    // Disabled.limit() is Some(0): set_capacity trims all retained entries.
    // Bare reclaim against a still-large Bounded budget may keep residents.
    store.set_object_cache_capacity(ObjectCacheCapacity::Disabled);
    store.reclaim_object_cache();
    assert_cache_empty(store.object_cache_stats())?;
    let capacity = ObjectCacheCapacity::Bounded(
        NonZeroU64::new(budget).ok_or("object cache budget must be greater than zero")?,
    );
    // Restore Bounded before the timed arm so retains during measure are accepted.
    store.set_object_cache_capacity(capacity);
    assert_cache_empty(store.object_cache_stats())?;
    Ok(())
}

fn assert_cache_empty(stats: ObjectCacheStats) -> BenchResult<()> {
    if stats.resident_bytes != 0
        || stats.resident_objects != 0
        || stats.resident_projection_bytes != 0
        || stats.resident_projection_entries != 0
    {
        return Err(format!(
            "object cache not empty before timed arm: resident_bytes={} resident_objects={} resident_projection_bytes={} resident_projection_entries={}",
            stats.resident_bytes,
            stats.resident_objects,
            stats.resident_projection_bytes,
            stats.resident_projection_entries
        )
        .into());
    }
    Ok(())
}
