use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Serialize;

const ESTIMATED_OBJECT_OVERHEAD_BYTES: u64 = 162;
const ESTIMATED_REFERENCE_RECORD_BYTES: u64 = 40;
const BASIS_POINTS: u64 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChunkSizeDistributionBytes {
    pub mean: u64,
    pub minimum: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub maximum: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Deduplication {
    pub retained_bytes: u64,
    pub saved_bytes: u64,
    pub retained_basis_points: u64,
    pub saved_basis_points: u64,
}

#[derive(Debug, Serialize)]
pub struct Measurements {
    pub files: u64,
    pub logical_bytes: u64,
    pub whole_file_unique_objects: u64,
    pub whole_file_deduplication: Deduplication,
    pub total_chunks: u64,
    pub chunked_file_chunks: u64,
    pub representation_records: u64,
    pub collapsed_repetition_records: u64,
    pub unique_chunks: u64,
    pub chunk_deduplication: Deduplication,
    pub estimated_unique_object_metadata_bytes: u64,
    pub estimated_reference_metadata_bytes: u64,
    pub estimated_unique_object_cost_bytes: u64,
    pub elapsed_nanoseconds: u128,
    pub chunk_size_distribution_bytes: Option<ChunkSizeDistributionBytes>,
    pub cdc_chunk_size_distribution_bytes: Option<ChunkSizeDistributionBytes>,
}

#[derive(Default)]
pub struct Accumulator {
    files: u64,
    logical_bytes: u64,
    whole_files: HashMap<[u8; 32], u64>,
    total_chunks: u64,
    representation_records: u64,
    unique_chunk_bytes: u64,
    chunks: HashMap<[u8; 32], u64>,
    chunk_lengths: Vec<(u64, u64)>,
    cdc_chunk_lengths: Vec<(u64, u64)>,
}

impl Accumulator {
    pub fn add_file(&mut self, bytes: &[u8]) -> Result<()> {
        let length = u64::try_from(bytes.len())?;
        self.add_file_identity(length, *blake3::hash(bytes).as_bytes())
    }

    pub fn add_file_identity(&mut self, length: u64, identity: [u8; 32]) -> Result<()> {
        self.files = checked_add(self.files, 1, "file count")?;
        self.logical_bytes = checked_add(self.logical_bytes, length, "logical byte count")?;
        match self.whole_files.entry(identity) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(length);
            },
            std::collections::hash_map::Entry::Occupied(entry) => {
                if *entry.get() != length {
                    bail!("BLAKE3 evidence collision with inconsistent file lengths");
                }
            },
        }
        Ok(())
    }

    pub fn add_whole_record(&mut self, bytes: &[u8]) -> Result<()> {
        self.add_record(bytes, 1, false)
    }

    pub fn add_chunk_record(&mut self, bytes: &[u8], logical_chunks: u64) -> Result<()> {
        self.add_record(bytes, logical_chunks, true)
    }

    fn add_record(&mut self, bytes: &[u8], logical_chunks: u64, cdc: bool) -> Result<()> {
        if logical_chunks == 0 {
            bail!("a representation record must cover at least one logical chunk");
        }
        let length = u64::try_from(bytes.len())?;
        self.total_chunks = checked_add(self.total_chunks, logical_chunks, "chunk count")?;
        self.representation_records = checked_add(
            self.representation_records,
            1,
            "representation record count",
        )?;
        self.chunk_lengths.push((length, logical_chunks));
        if cdc {
            self.cdc_chunk_lengths.push((length, logical_chunks));
        }
        insert_identity(&mut self.chunks, bytes, &mut self.unique_chunk_bytes)
    }

    pub fn finish(mut self, elapsed: Duration) -> Result<Measurements> {
        self.chunk_lengths.sort_unstable();
        self.cdc_chunk_lengths.sort_unstable();
        let unique_chunks = u64::try_from(self.chunks.len())?;
        let whole_file_unique_objects = u64::try_from(self.whole_files.len())?;
        let whole_file_unique_bytes =
            self.whole_files.values().try_fold(0_u64, |total, length| {
                checked_add(total, *length, "whole-file unique bytes")
            })?;
        let estimated_unique_object_metadata_bytes = unique_chunks
            .checked_mul(ESTIMATED_OBJECT_OVERHEAD_BYTES)
            .ok_or_else(|| anyhow::anyhow!("metadata estimate overflow"))?;
        let estimated_reference_metadata_bytes = self
            .representation_records
            .checked_mul(ESTIMATED_REFERENCE_RECORD_BYTES)
            .ok_or_else(|| anyhow::anyhow!("reference metadata estimate overflow"))?;
        let estimated_unique_object_cost_bytes = checked_add(
            checked_add(
                self.unique_chunk_bytes,
                estimated_unique_object_metadata_bytes,
                "retained byte estimate",
            )?,
            estimated_reference_metadata_bytes,
            "retained byte estimate",
        )?;
        let chunk_size_distribution_bytes = optional_distribution(&self.chunk_lengths)?;
        Ok(Measurements {
            files: self.files,
            logical_bytes: self.logical_bytes,
            whole_file_unique_objects,
            whole_file_deduplication: deduplication(self.logical_bytes, whole_file_unique_bytes)?,
            total_chunks: self.total_chunks,
            chunked_file_chunks: weighted_count(&self.cdc_chunk_lengths)?,
            representation_records: self.representation_records,
            collapsed_repetition_records: self
                .total_chunks
                .checked_sub(self.representation_records)
                .ok_or_else(|| anyhow::anyhow!("representation records exceed logical chunks"))?,
            unique_chunks,
            chunk_deduplication: deduplication(self.logical_bytes, self.unique_chunk_bytes)?,
            estimated_unique_object_metadata_bytes,
            estimated_reference_metadata_bytes,
            estimated_unique_object_cost_bytes,
            elapsed_nanoseconds: elapsed.as_nanos(),
            chunk_size_distribution_bytes,
            cdc_chunk_size_distribution_bytes: optional_distribution(&self.cdc_chunk_lengths)?,
        })
    }
}

fn insert_identity(
    identities: &mut HashMap<[u8; 32], u64>,
    bytes: &[u8],
    unique_bytes: &mut u64,
) -> Result<()> {
    let length = u64::try_from(bytes.len())?;
    let identity = *blake3::hash(bytes).as_bytes();
    match identities.entry(identity) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(length);
            *unique_bytes = checked_add(*unique_bytes, length, "unique byte count")?;
        },
        std::collections::hash_map::Entry::Occupied(entry) => {
            if *entry.get() != length {
                bail!("BLAKE3 evidence collision with inconsistent lengths");
            }
        },
    }
    Ok(())
}

fn deduplication(logical_bytes: u64, retained_bytes: u64) -> Result<Deduplication> {
    if retained_bytes > logical_bytes {
        bail!("retained bytes exceed logical bytes");
    }
    let saved_bytes = logical_bytes
        .checked_sub(retained_bytes)
        .ok_or_else(|| anyhow::anyhow!("retained bytes exceed logical bytes"))?;
    Ok(Deduplication {
        retained_bytes,
        saved_bytes,
        retained_basis_points: basis_points(retained_bytes, logical_bytes)?,
        saved_basis_points: basis_points(saved_bytes, logical_bytes)?,
    })
}

/// Returns the ratio in basis points, rounded down.
///
/// Retained and saved ratios are deliberately calculated independently with
/// this same rule. Deriving one as the complement of the other would round one
/// side up whenever the exact ratio is fractional.
fn basis_points(part: u64, total: u64) -> Result<u64> {
    if total == 0 {
        return Ok(0);
    }
    part.checked_mul(BASIS_POINTS)
        .and_then(|value| value.checked_div(total))
        .ok_or_else(|| anyhow::anyhow!("dedup ratio overflow"))
}

fn distribution(sorted: &[(u64, u64)]) -> Result<ChunkSizeDistributionBytes> {
    if sorted.is_empty() {
        bail!("a corpus produced no chunks");
    }
    let count = weighted_count(sorted)?;
    let sum = sorted.iter().try_fold(0_u64, |sum, (length, weight)| {
        let weighted = length
            .checked_mul(*weight)
            .ok_or_else(|| anyhow::anyhow!("weighted chunk length overflow"))?;
        checked_add(sum, weighted, "chunk-length sum")
    })?;
    let mean = sum
        .checked_div(count)
        .ok_or_else(|| anyhow::anyhow!("chunk distribution is empty"))?;
    Ok(ChunkSizeDistributionBytes {
        mean,
        minimum: sorted[0].0,
        p50: percentile(sorted, 50)?,
        p95: percentile(sorted, 95)?,
        p99: percentile(sorted, 99)?,
        maximum: sorted
            .last()
            .ok_or_else(|| anyhow::anyhow!("chunk distribution is empty"))?
            .0,
    })
}

fn optional_distribution(sorted: &[(u64, u64)]) -> Result<Option<ChunkSizeDistributionBytes>> {
    if sorted.is_empty() {
        Ok(None)
    } else {
        distribution(sorted).map(Some)
    }
}

fn weighted_count(sorted: &[(u64, u64)]) -> Result<u64> {
    sorted.iter().try_fold(0_u64, |count, (_, weight)| {
        checked_add(count, *weight, "chunk count")
    })
}

fn percentile(sorted: &[(u64, u64)], percentile: u64) -> Result<u64> {
    let total = sorted.iter().try_fold(0_u64, |count, (_, weight)| {
        checked_add(count, *weight, "chunk count")
    })?;
    let last = total
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("chunk distribution is empty"))?;
    let index = last
        .checked_mul(percentile)
        .and_then(|value| value.checked_add(99))
        .ok_or_else(|| anyhow::anyhow!("percentile index overflow"))?
        / 100;
    let mut cumulative = 0_u64;
    for (length, weight) in sorted {
        cumulative = checked_add(cumulative, *weight, "chunk count")?;
        if cumulative > index {
            return Ok(*length);
        }
    }
    bail!("percentile index is outside the distribution")
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| anyhow::anyhow!("{label} overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_ratios_are_exact_basis_points() {
        assert_eq!(
            deduplication(1_000, 471).unwrap(),
            Deduplication {
                retained_bytes: 471,
                saved_bytes: 529,
                retained_basis_points: 4_710,
                saved_basis_points: 5_290,
            }
        );
        assert_eq!(
            deduplication(3, 1).unwrap(),
            Deduplication {
                retained_bytes: 1,
                saved_bytes: 2,
                retained_basis_points: 3_333,
                saved_basis_points: 6_666,
            }
        );
        assert_eq!(
            deduplication(0, 0).unwrap(),
            Deduplication {
                retained_bytes: 0,
                saved_bytes: 0,
                retained_basis_points: 0,
                saved_basis_points: 0,
            }
        );
    }

    #[test]
    fn repeated_whole_files_and_chunks_are_counted_independently() {
        let mut accumulator = Accumulator::default();
        accumulator.add_file(b"same").unwrap();
        accumulator.add_chunk_record(b"sa", 1).unwrap();
        accumulator.add_chunk_record(b"me", 1).unwrap();
        accumulator.add_file(b"same").unwrap();
        accumulator.add_chunk_record(b"sa", 1).unwrap();
        accumulator.add_chunk_record(b"me", 1).unwrap();
        let measurements = accumulator.finish(Duration::ZERO).unwrap();
        assert_eq!(measurements.whole_file_unique_objects, 1);
        assert_eq!(
            measurements.whole_file_deduplication.saved_basis_points,
            5_000
        );
        assert_eq!(measurements.unique_chunks, 2);
        assert_eq!(measurements.chunk_deduplication.saved_basis_points, 5_000);
    }

    #[test]
    fn an_all_empty_corpus_has_no_chunk_distribution() {
        let mut accumulator = Accumulator::default();
        accumulator.add_file(b"").unwrap();
        accumulator.add_file(b"").unwrap();
        let measurements = accumulator.finish(Duration::ZERO).unwrap();

        assert_eq!(measurements.files, 2);
        assert_eq!(measurements.total_chunks, 0);
        assert_eq!(measurements.chunk_size_distribution_bytes, None);
        assert_eq!(measurements.cdc_chunk_size_distribution_bytes, None);
    }
}
