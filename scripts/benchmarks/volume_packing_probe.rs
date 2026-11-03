//! Owned public HostedFileVolume packing/page-cost diagnostic.
//!
//! Same frozen source for main and candidate. Not a CI gate and not speed
//! acceptance. Emits machine-readable key=value lines on stdout.
//!
//! Matched legacy-compatible counts: 32768 and 600000 (both arms).
//! Beyond-legacy conversion count: 699051 (candidate-only absolute paged cost).
//! Do not invent parity thresholds or claim matched speed past main capacity.

use astrid_storage::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// ASTMAP1 ceiling used by the public capacity regression: 16 MiB / 24 + 1.
const LEGACY_CAPACITY_EXTENTS: u64 = (16 * 1024 * 1024) / 24 + 1;
const MAX_EXTENTS: u64 = 1_000_000;
const MATCHED_HINTS: [u64; 2] = [32_768, 600_000];

fn main() {
    if let Err(error) = run() {
        eprintln!("probe_error={error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: probe <new-volume-path> <extent_count> <region_count>",
        ));
    }
    let path = PathBuf::from(&args[1]);
    let extent_count: u64 = args[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "extent_count"))?;
    let region_count: u64 = args[3]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region_count"))?;
    guard_path(&path)?;
    if extent_count == 0 || extent_count > MAX_EXTENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "extent_count must be 1..=1000000",
        ));
    }
    if region_count != 1 && region_count != 7 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "region_count must be 1 or 7",
        ));
    }

    let beyond_legacy = extent_count >= LEGACY_CAPACITY_EXTENTS;
    let matched_legacy_compatible = MATCHED_HINTS.contains(&extent_count);
    kv("probe", "pr2207-public-volume-packing-probe-20261103");
    kv("path", &path.display().to_string());
    kv_u64("extent_count", extent_count);
    kv_u64("region_count", region_count);
    kv_u64("legacy_capacity_extents", LEGACY_CAPACITY_EXTENTS);
    kv_bool("beyond_legacy_capacity", beyond_legacy);
    kv_bool("matched_legacy_compatible_count", matched_legacy_compatible);
    kv_bool("candidate_only_conversion_count", beyond_legacy);
    kv("allocation_logging", "false");
    kv("speed_acceptance", "NOT_CLAIMED");
    kv(
        "method_gap_physical_uncached",
        "logical_random_reads_only;_public_API_has_no_O_DIRECT",
    );
    kv(
        "method_gap_checkpoint_format",
        "not_exposed_on_public_API;_infer_from_count_and_arm",
    );
    kv(
        "method_gap_drop_io",
        "size_unchanged_asserted;_Drop_may_still_touch_footer_without_growth",
    );
    kv(
        "method_gap_main_at_699051",
        "final_checkpoint_expected_to_fail_on_main_legacy_capacity",
    );

    let regions = build_regions(region_count)?;
    let writer = HostedFileVolume::open(&path)?;
    for region in &regions {
        writer.create_region(region, true)?;
    }

    let midpoint = extent_count / 2;
    let mut phase = Instant::now();
    let mut setup_write_ns: u128 = 0;
    let mut midpoint_sync_s = 0.0_f64;

    for index in 0..extent_count {
        let (region, offset) = map_extent(index, region_count);
        let value = [byte_at(index)];
        writer.write_region_at(&regions[region], offset, &value)?;

        if index + 1 == midpoint && midpoint > 0 {
            setup_write_ns += phase.elapsed().as_nanos();
            let sync_started = Instant::now();
            writer.sync()?;
            midpoint_sync_s = sync_started.elapsed().as_secs_f64();
            phase = Instant::now();
        }
    }
    setup_write_ns += phase.elapsed().as_nanos();
    let setup_writes_s = (setup_write_ns as f64) / 1_000_000_000.0;
    kv_f64("setup_writes_s", setup_writes_s);
    kv_f64("midpoint_sync_s", midpoint_sync_s);

    let checkpoint_started = Instant::now();
    writer.sync()?;
    let final_checkpoint_s = checkpoint_started.elapsed().as_secs_f64();
    kv_f64("final_checkpoint_s", final_checkpoint_s);

    let acknowledged_bytes = file_len(&path)?;
    kv_u64("volume_bytes_after_final_checkpoint", acknowledged_bytes);

    // Clean sync after an acknowledged checkpoint must not grow the container.
    writer.sync()?;
    let after_clean = file_len(&path)?;
    if after_clean != acknowledged_bytes {
        return Err(io::Error::other(format!(
            "clean sync mutated size {acknowledged_bytes} -> {after_clean}"
        )));
    }
    kv_bool("clean_sync_size_unchanged", true);

    // Drop the live handle instead of fs::copy. After a clean acknowledged
    // sync, Drop must not introduce new mutations visible as size growth.
    drop(writer);
    let after_drop = file_len(&path)?;
    if after_drop != acknowledged_bytes {
        return Err(io::Error::other(format!(
            "drop after clean sync mutated size {acknowledged_bytes} -> {after_drop}"
        )));
    }
    kv_bool("drop_after_clean_sync_size_unchanged", true);

    let reopen_started = Instant::now();
    let volume = HostedFileVolume::open(&path)?;
    let fresh_reopen_s = reopen_started.elapsed().as_secs_f64();
    kv_f64("fresh_reopen_s", fresh_reopen_s);
    if file_len(&path)? != acknowledged_bytes {
        return Err(io::Error::other("reopen changed volume size"));
    }

    for (region_index, region) in regions.iter().enumerate() {
        let expected_len = region_len_for(extent_count, region_count, region_index as u64);
        if volume.region_len(region)? != expected_len {
            return Err(io::Error::other(format!(
                "region {} len mismatch",
                region.as_str()
            )));
        }
    }

    let mut checksum: u64 = 0;
    let readback_started = Instant::now();
    for (region_index, region) in regions.iter().enumerate() {
        let expected_len = region_len_for(extent_count, region_count, region_index as u64);
        let mut bytes = vec![0_u8; usize::try_from(expected_len).expect("region fits usize")];
        let read = volume.read_region_at(region, 0, &mut bytes)?;
        if read as u64 != expected_len {
            return Err(io::Error::other("short full readback"));
        }
        for (offset, actual) in bytes.iter().enumerate() {
            let global = (offset as u64)
                .checked_mul(region_count)
                .and_then(|v| v.checked_add(region_index as u64))
                .expect("global index");
            let expected = byte_at(global);
            if *actual != expected {
                return Err(io::Error::other(format!(
                    "full readback mismatch at global={global}"
                )));
            }
            checksum = mix(checksum, global, *actual);
        }
    }
    let full_exact_readback_s = readback_started.elapsed().as_secs_f64();
    kv_f64("full_exact_readback_s", full_exact_readback_s);
    kv_u64("checksum_after_full_readback", checksum);

    // Many independent one-byte logical reads. This is the page-auth stress:
    // do not treat the contiguous scan above as sufficient.
    let random_reads = random_read_count(extent_count);
    let mut random_checksum: u64 = 0;
    let random_started = Instant::now();
    for sample in 0..random_reads {
        let global = random_extent(sample, extent_count);
        let (region, offset) = map_extent(global, region_count);
        let mut byte = [0_u8; 1];
        let read = volume.read_region_at(&regions[region], offset, &mut byte)?;
        if read != 1 || byte[0] != byte_at(global) {
            return Err(io::Error::other(format!(
                "random read mismatch sample={sample} global={global}"
            )));
        }
        random_checksum = mix(random_checksum, global, byte[0]);
    }
    let random_small_read_s = random_started.elapsed().as_secs_f64();
    kv_u64("random_small_read_count", random_reads);
    kv_u64("random_small_read_bytes_each", 1);
    kv_f64("random_small_read_s", random_small_read_s);
    kv_u64("checksum_random_reads", random_checksum);

    // Dirty acknowledged updates, then drop/reopen exact restart (no copy).
    let dirty_count = dirty_update_count(extent_count);
    // Build the independent expected-state set outside every measured interval.
    let dirty_offsets: BTreeSet<u64> = (0..dirty_count)
        .map(|sample| dirty_extent(sample, extent_count))
        .collect();
    for sample in 0..dirty_count {
        let global = dirty_extent(sample, extent_count);
        let (region, offset) = map_extent(global, region_count);
        let value = [dirty_byte_at(global)];
        volume.write_region_at(&regions[region], offset, &value)?;
    }
    let dirty_sync_started = Instant::now();
    volume.sync()?;
    let dirty_sync_s = dirty_sync_started.elapsed().as_secs_f64();
    kv_u64("dirty_update_count", dirty_count);
    kv_f64("dirty_sync_s", dirty_sync_s);
    let dirty_bytes = file_len(&path)?;
    kv_u64("volume_bytes_after_dirty_sync", dirty_bytes);

    volume.sync()?;
    if file_len(&path)? != dirty_bytes {
        return Err(io::Error::other("clean sync after dirty mutated size"));
    }
    drop(volume);
    if file_len(&path)? != dirty_bytes {
        return Err(io::Error::other("drop after dirty clean sync mutated size"));
    }

    let restart_started = Instant::now();
    let restarted = HostedFileVolume::open(&path)?;
    let dirty_restart_reopen_s = restart_started.elapsed().as_secs_f64();
    kv_f64("dirty_restart_reopen_s", dirty_restart_reopen_s);

    let mut restart_checksum: u64 = 0;
    let restart_read_started = Instant::now();
    for (region_index, region) in regions.iter().enumerate() {
        let expected_len = region_len_for(extent_count, region_count, region_index as u64);
        let mut bytes = vec![0_u8; usize::try_from(expected_len).expect("region fits usize")];
        let read = restarted.read_region_at(region, 0, &mut bytes)?;
        if read as u64 != expected_len {
            return Err(io::Error::other("short dirty restart readback"));
        }
        for (offset, actual) in bytes.iter().enumerate() {
            let global = (offset as u64)
                .checked_mul(region_count)
                .and_then(|v| v.checked_add(region_index as u64))
                .expect("global index");
            let expected = if dirty_offsets.contains(&global) {
                dirty_byte_at(global)
            } else {
                byte_at(global)
            };
            if *actual != expected {
                return Err(io::Error::other(format!(
                    "dirty restart mismatch at global={global}"
                )));
            }
            restart_checksum = mix(restart_checksum, global, *actual);
        }
    }
    let dirty_restart_exact_readback_s = restart_read_started.elapsed().as_secs_f64();
    kv_f64(
        "dirty_restart_exact_readback_s",
        dirty_restart_exact_readback_s,
    );
    kv_u64("checksum_after_dirty_restart", restart_checksum);
    kv_bool("exact_readback_including_dirty_updates", true);
    kv_bool("used_fs_copy", false);
    kv_bool("complete", true);
    let _ = restarted;
    let _ = io::stdout().flush();
    Ok(())
}

fn guard_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume path must be absolute",
        ));
    }
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "owned fixture volume path must be new",
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume path has no parent",
        ));
    };
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "parent directory must already exist; probe will not create fixture trees",
        ));
    }
    // Refuse opening through a missing final component that is not a plain file name.
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume path has no file name",
        ));
    }
    Ok(())
}

fn build_regions(region_count: u64) -> io::Result<Vec<VolumeRegion>> {
    let mut regions = Vec::with_capacity(usize::try_from(region_count).expect("region_count"));
    for index in 0..region_count {
        regions.push(VolumeRegion::new(format!("region-{index}"))?);
    }
    Ok(regions)
}

fn map_extent(index: u64, region_count: u64) -> (usize, u64) {
    let region = usize::try_from(index % region_count).expect("region index");
    let offset = index / region_count;
    (region, offset)
}

fn region_len_for(extent_count: u64, region_count: u64, region_index: u64) -> u64 {
    if region_index >= extent_count {
        return 0;
    }
    (extent_count - 1 - region_index) / region_count + 1
}

fn byte_at(index: u64) -> u8 {
    (index % 251) as u8
}

fn dirty_byte_at(index: u64) -> u8 {
    byte_at(index).wrapping_add(97)
}

fn dirty_update_count(extent_count: u64) -> u64 {
    extent_count.min(4_096)
}

fn dirty_extent(sample: u64, extent_count: u64) -> u64 {
    // Distinct from the random-read stride so dirty set is deterministic and stable.
    sample.wrapping_mul(1103515245).wrapping_add(12345) % extent_count
}

fn random_read_count(extent_count: u64) -> u64 {
    extent_count.min(65_536)
}

fn random_extent(sample: u64, extent_count: u64) -> u64 {
    sample.wrapping_mul(7919) % extent_count
}

fn mix(checksum: u64, offset: u64, byte: u8) -> u64 {
    checksum
        .wrapping_mul(131)
        .wrapping_add(offset)
        .wrapping_add(u64::from(byte))
}

fn file_len(path: &Path) -> io::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

fn kv(key: &str, value: &str) {
    println!("{key}={value}");
}

fn kv_bool(key: &str, value: bool) {
    println!("{key}={}", if value { "true" } else { "false" });
}

fn kv_u64(key: &str, value: u64) {
    println!("{key}={value}");
}

fn kv_f64(key: &str, value: f64) {
    println!("{key}={value:.9}");
}
