use std::hint::black_box;
use std::io::Cursor;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::Serialize;

use crate::algorithm::Candidate;
use crate::fixture::pseudorandom_bytes;

const FIXTURE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_SAMPLES: usize = 3;

#[derive(Debug, Serialize)]
pub struct ThroughputResult {
    pub candidate: String,
    pub fixture_bytes: u64,
    pub samples: u64,
    pub chunk_only: Timing,
    pub chunk_and_blake3: Timing,
}

#[derive(Debug, Serialize)]
pub struct Timing {
    pub median_nanoseconds: u128,
    pub minimum_nanoseconds: u128,
    pub median_bytes_per_second: u64,
    pub median_mib_per_second_times_100: u64,
}

pub fn measure(candidate: &Candidate) -> Result<ThroughputResult> {
    let fixture = pseudorandom_bytes(FIXTURE_BYTES, 0xbb67_ae85_84ca_a73b);
    let chunk_only = samples(candidate, &fixture, false, DEFAULT_SAMPLES)?;
    let chunk_and_blake3 = samples(candidate, &fixture, true, DEFAULT_SAMPLES)?;
    Ok(ThroughputResult {
        candidate: candidate.name.clone(),
        fixture_bytes: u64::try_from(fixture.len())?,
        samples: u64::try_from(DEFAULT_SAMPLES)?,
        chunk_only,
        chunk_and_blake3,
    })
}

fn samples(
    candidate: &Candidate,
    fixture: &[u8],
    hash_chunks: bool,
    count: usize,
) -> Result<Timing> {
    if count == 0 {
        bail!("throughput sample count must be non-zero");
    }
    let mut durations = Vec::with_capacity(count);
    for _ in 0..count {
        let started = Instant::now();
        let mut guard = [0_u8; 32];
        candidate.visit_records(Cursor::new(fixture), |bytes, logical_chunks| {
            if hash_chunks {
                fold_digest(&mut guard, blake3::hash(bytes).as_bytes());
            } else {
                guard[0] ^= bytes.first().copied().unwrap_or_default();
                guard[1] ^= u8::try_from(logical_chunks & 0xff)?;
            }
            Ok(())
        })?;
        black_box(guard);
        durations.push(started.elapsed());
    }
    durations.sort_unstable();
    timing(
        u64::try_from(fixture.len())?,
        durations[durations.len() / 2],
        durations[0],
    )
}

pub(crate) fn fold_digest(guard: &mut [u8; 32], digest: &[u8; 32]) {
    for (guard_byte, digest_byte) in guard.iter_mut().zip(digest) {
        *guard_byte ^= digest_byte;
    }
}

pub(crate) fn timing(bytes: u64, median: Duration, minimum: Duration) -> Result<Timing> {
    let median_nanoseconds = median.as_nanos();
    let bytes_per_second = u128::from(bytes)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_div(median_nanoseconds))
        .ok_or_else(|| anyhow::anyhow!("throughput timing is zero or overflowed"))?;
    let mib_per_second_times_100 = bytes_per_second
        .checked_mul(100)
        .and_then(|value| value.checked_div(1024 * 1024))
        .ok_or_else(|| anyhow::anyhow!("throughput conversion overflow"))?;
    Ok(Timing {
        median_nanoseconds,
        minimum_nanoseconds: minimum.as_nanos(),
        median_bytes_per_second: u64::try_from(bytes_per_second)?,
        median_mib_per_second_times_100: u64::try_from(mib_per_second_times_100)?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn rate_conversion_is_integer_and_explicit() {
        let result = timing(
            1024 * 1024,
            Duration::from_millis(500),
            Duration::from_millis(400),
        )
        .unwrap();
        assert_eq!(result.median_bytes_per_second, 2 * 1024 * 1024);
        assert_eq!(result.median_mib_per_second_times_100, 200);
    }

    #[test]
    fn every_chunk_digest_contributes_to_the_guard() {
        let first = *blake3::hash(b"first").as_bytes();
        let second = *blake3::hash(b"second").as_bytes();
        let mut guard = [0_u8; 32];
        fold_digest(&mut guard, &first);
        fold_digest(&mut guard, &second);
        assert_ne!(guard, first);
        assert_ne!(guard, second);
    }
}
