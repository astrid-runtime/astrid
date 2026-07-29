use std::io::Read;

use anyhow::{Result, bail};
use fastcdc::v2020::{Normalization, StreamCDC};
use mincdc::{MinCdcHash4, ReadChunker};
use mothcdc::MothReadChunker;
use serde::Serialize;

pub const MINCDC_MULTIPLIER: u32 = 0x915f_77f5;
pub const MINCDC_ADDEND: u32 = 0x3463_6463;
pub const MINCDC_WINDOW_BYTES: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    FastCdc2020,
    MinCdcHash4,
    MothCaterpillar,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Candidate {
    pub name: String,
    pub algorithm: Algorithm,
    pub minimum_bytes: u32,
    pub maximum_bytes: u32,
    pub implementation: &'static str,
    pub boundary_semantics: BoundarySemantics,
    pub parameters: Parameters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BoundarySemantics {
    pub non_final_bounds: &'static str,
    pub final_chunk: &'static str,
    pub tie_break: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Parameters {
    FastCdc2020 {
        target_bytes: u32,
        normalization_level: u8,
        gear_seed: u64,
    },
    MinCdcHash4 {
        window_bytes: u8,
        multiplier: u32,
        addend: u32,
    },
    MothCaterpillar {
        boundary_algorithm: &'static str,
        repeated_chunk_representation: &'static str,
    },
}

impl Candidate {
    /// Visits the physical records produced by the candidate.
    ///
    /// `logical_chunks` is greater than one only for Moth's optional
    /// adjacent-identical-chunk representation. The boundary algorithm remains
    /// `MinCDC` and is measured independently by the paired `MinCDC` candidate.
    pub fn visit_records<R, F>(&self, reader: R, mut visit: F) -> Result<()>
    where
        R: Read,
        F: FnMut(&[u8], u64) -> Result<()>,
    {
        let minimum = usize::try_from(self.minimum_bytes)?;
        let maximum = usize::try_from(self.maximum_bytes)?;
        match self.algorithm {
            Algorithm::FastCdc2020 => {
                let target = usize::try_from(self.fastcdc_target_bytes()?)?;
                for chunk in StreamCDC::with_level_and_seed(
                    reader,
                    minimum,
                    target,
                    maximum,
                    Normalization::Level1,
                    0,
                ) {
                    visit(&chunk?.data, 1)?;
                }
            },
            Algorithm::MinCdcHash4 => {
                visit_min_cdc(reader, minimum, maximum, &mut visit)?;
            },
            Algorithm::MothCaterpillar => {
                let mut chunker = MothReadChunker::try_new(reader, minimum, maximum)?;
                while let Some(segment) = chunker.next()? {
                    visit(segment.dedup_key(), segment.chunk_count())?;
                }
            },
        }
        Ok(())
    }

    /// Visits logical chunk boundaries without Moth's representation collapse.
    pub fn visit_boundary_chunks<R, F>(&self, reader: R, mut visit: F) -> Result<()>
    where
        R: Read,
        F: FnMut(&[u8]) -> Result<()>,
    {
        let minimum = usize::try_from(self.minimum_bytes)?;
        let maximum = usize::try_from(self.maximum_bytes)?;
        match self.algorithm {
            Algorithm::FastCdc2020 => {
                let target = usize::try_from(self.fastcdc_target_bytes()?)?;
                for chunk in StreamCDC::with_level_and_seed(
                    reader,
                    minimum,
                    target,
                    maximum,
                    Normalization::Level1,
                    0,
                ) {
                    visit(&chunk?.data)?;
                }
            },
            Algorithm::MinCdcHash4 => {
                visit_min_cdc(reader, minimum, maximum, |chunk, count| {
                    debug_assert_eq!(count, 1);
                    visit(chunk)
                })?;
            },
            Algorithm::MothCaterpillar => {
                let mut chunker = MothReadChunker::try_new(reader, minimum, maximum)?;
                while let Some(segment) = chunker.next()? {
                    for _ in 0..segment.chunk_count() {
                        visit(segment.dedup_key())?;
                    }
                }
            },
        }
        Ok(())
    }

    fn fastcdc_target_bytes(&self) -> Result<u32> {
        match self.parameters {
            Parameters::FastCdc2020 { target_bytes, .. } => Ok(target_bytes),
            _ => bail!("FastCDC candidate has non-FastCDC parameters"),
        }
    }
}

pub fn candidates(target_kib: u32) -> Result<Vec<Candidate>> {
    if !(8..=256).contains(&target_kib) || !target_kib.is_power_of_two() {
        bail!("target KiB must be a power of two in 8..=256");
    }
    let target = target_kib
        .checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("target byte size overflow"))?;

    let fast_minimum = target / 4;
    let fast_maximum = target
        .checked_mul(4)
        .ok_or_else(|| anyhow::anyhow!("FastCDC maximum overflow"))?;
    let narrow_minimum = checked_ratio(target, 3, 4, "narrow MinCDC minimum")?;
    let narrow_maximum = checked_ratio(target, 5, 4, "narrow MinCDC maximum")?;
    let wide_minimum = target / 2;
    let wide_maximum = checked_ratio(target, 3, 2, "wide MinCDC maximum")?;
    let observed_match_minimum = target / 2;
    let observed_match_maximum = checked_ratio(target, 5, 2, "observed-match MinCDC maximum")?;
    let observed_match_kib = target_kib
        .checked_mul(3)
        .and_then(|value| value.checked_div(2))
        .ok_or_else(|| anyhow::anyhow!("observed-match label overflow"))?;

    Ok(vec![
        Candidate {
            name: format!("fastcdc-v2020-{target_kib}k"),
            algorithm: Algorithm::FastCdc2020,
            minimum_bytes: fast_minimum,
            maximum_bytes: fast_maximum,
            implementation: "fastcdc=4.0.1",
            boundary_semantics: BoundarySemantics {
                non_final_bounds: "minimum <= length <= maximum",
                final_chunk: "may be shorter than minimum; never exceeds maximum",
                tie_break: "FastCDC v2020 gear-mask rule; seed zero",
            },
            parameters: Parameters::FastCdc2020 {
                target_bytes: target,
                normalization_level: 1,
                gear_seed: 0,
            },
        },
        mincdc_candidate(
            format!("mincdc-hash4-narrow-{target_kib}k"),
            narrow_minimum,
            narrow_maximum,
        ),
        mothcdc_candidate(
            format!("moth-caterpillar-narrow-{target_kib}k"),
            narrow_minimum,
            narrow_maximum,
        ),
        mincdc_candidate(
            format!("mincdc-hash4-wide-{target_kib}k"),
            wide_minimum,
            wide_maximum,
        ),
        mothcdc_candidate(
            format!("moth-caterpillar-wide-{target_kib}k"),
            wide_minimum,
            wide_maximum,
        ),
        mincdc_candidate(
            format!("mincdc-hash4-observed-match-{observed_match_kib}k"),
            observed_match_minimum,
            observed_match_maximum,
        ),
        mothcdc_candidate(
            format!("moth-caterpillar-observed-match-{observed_match_kib}k"),
            observed_match_minimum,
            observed_match_maximum,
        ),
        mincdc_candidate(
            format!("mincdc-hash4-fastcdc-bounds-{target_kib}k"),
            fast_minimum,
            fast_maximum,
        ),
    ])
}

fn visit_min_cdc<R, F>(reader: R, minimum: usize, maximum: usize, mut visit: F) -> Result<()>
where
    R: Read,
    F: FnMut(&[u8], u64) -> Result<()>,
{
    let mut chunker = ReadChunker::new(
        reader,
        minimum,
        maximum,
        MinCdcHash4::with_params(MINCDC_MULTIPLIER, MINCDC_ADDEND),
    );
    while let Some(chunk) = chunker.next()? {
        visit(&chunk, 1)?;
    }
    Ok(())
}

fn mothcdc_candidate(name: String, minimum: u32, maximum: u32) -> Candidate {
    Candidate {
        name,
        algorithm: Algorithm::MothCaterpillar,
        minimum_bytes: minimum,
        maximum_bytes: maximum,
        implementation: "mothcdc=0.7.2 (evidence oracle only)",
        boundary_semantics: min_cdc_boundary_semantics(),
        parameters: Parameters::MothCaterpillar {
            boundary_algorithm: "MinCdcHash4 with mincdc=0.1.0 default constants",
            repeated_chunk_representation: "one record for an adjacent run of byte-identical chunks",
        },
    }
}

fn mincdc_candidate(name: String, minimum: u32, maximum: u32) -> Candidate {
    Candidate {
        name,
        algorithm: Algorithm::MinCdcHash4,
        minimum_bytes: minimum,
        maximum_bytes: maximum,
        implementation: "mincdc=0.1.0 (evidence oracle only)",
        boundary_semantics: min_cdc_boundary_semantics(),
        parameters: Parameters::MinCdcHash4 {
            window_bytes: MINCDC_WINDOW_BYTES,
            multiplier: MINCDC_MULTIPLIER,
            addend: MINCDC_ADDEND,
        },
    }
}

const fn min_cdc_boundary_semantics() -> BoundarySemantics {
    BoundarySemantics {
        non_final_bounds: "minimum <= length <= maximum",
        final_chunk: "may be shorter than minimum; never exceeds maximum",
        tie_break: "leftmost minimum 4-byte rolling-hash value",
    }
}

fn checked_ratio(value: u32, numerator: u32, denominator: u32, label: &str) -> Result<u32> {
    value
        .checked_mul(numerator)
        .and_then(|product| product.checked_div(denominator))
        .ok_or_else(|| anyhow::anyhow!("{label} overflow"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::fixture::pseudorandom_bytes;

    use super::*;

    #[test]
    fn min_cdc_candidates_encode_bounds_without_a_fake_target() {
        let candidates = candidates(64).unwrap();
        for candidate in &candidates[1..] {
            assert!(matches!(
                candidate.parameters,
                Parameters::MinCdcHash4 { .. } | Parameters::MothCaterpillar { .. }
            ));
            assert!(
                !serde_json::to_string(candidate)
                    .unwrap()
                    .contains("target_bytes")
            );
        }
        let observed = candidate(&candidates, "mincdc-hash4-observed-match-96k");
        assert_eq!(
            observed
                .minimum_bytes
                .checked_add(observed.maximum_bytes)
                .unwrap()
                / 2,
            96 * 1024
        );
        let fastcdc = candidate(&candidates, "fastcdc-v2020-64k");
        assert!(
            serde_json::to_string(fastcdc)
                .unwrap()
                .contains("\"target_bytes\":65536")
        );
    }

    #[test]
    fn moth_and_min_cdc_share_underlying_boundaries() {
        let candidates = candidates(8).unwrap();
        let mincdc = candidate(&candidates, "mincdc-hash4-narrow-8k");
        let mothcdc = candidate(&candidates, "moth-caterpillar-narrow-8k");
        let data = pseudorandom_bytes(1_000_000, 0xc0de_cafe_5eed_f00d);
        assert_eq!(
            boundary_lengths(mincdc, &data),
            boundary_lengths(mothcdc, &data)
        );
    }

    #[test]
    fn every_non_final_chunk_respects_declared_bounds() {
        let data = (0..2_000_000_u64)
            .map(|index| {
                let mixed = index.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
                mixed.to_le_bytes()[0]
            })
            .collect::<Vec<_>>();
        for candidate in candidates(8).unwrap() {
            let lengths = boundary_lengths(&candidate, &data);
            assert!(!lengths.is_empty());
            for length in &lengths[..lengths.len() - 1] {
                assert!(*length >= usize::try_from(candidate.minimum_bytes).unwrap());
                assert!(*length <= usize::try_from(candidate.maximum_bytes).unwrap());
            }
            assert!(*lengths.last().unwrap() <= usize::try_from(candidate.maximum_bytes).unwrap());
        }
    }

    #[test]
    fn oracle_boundaries_are_deterministic() {
        let data = (0..1_000_000_u64)
            .map(|index| index.wrapping_mul(31).to_le_bytes()[2])
            .collect::<Vec<_>>();
        for candidate in candidates(8).unwrap() {
            assert_eq!(
                boundary_lengths(&candidate, &data),
                boundary_lengths(&candidate, &data)
            );
        }
    }

    fn candidate<'a>(candidates: &'a [Candidate], name: &str) -> &'a Candidate {
        candidates
            .iter()
            .find(|candidate| candidate.name == name)
            .unwrap()
    }

    fn boundary_lengths(candidate: &Candidate, data: &[u8]) -> Vec<usize> {
        let mut lengths = Vec::new();
        candidate
            .visit_boundary_chunks(Cursor::new(data), |chunk| {
                lengths.push(chunk.len());
                Ok(())
            })
            .unwrap();
        lengths
    }
}
