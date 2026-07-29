use std::collections::HashSet;
use std::io::Cursor;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::algorithm::Candidate;
use crate::fixture::pseudorandom_bytes;

const FIXTURE_BYTES: usize = 8 * 1024 * 1024;
const EDIT_BYTES: usize = 257;
const NEIGHBORHOOD_QUANTILES_BASIS_POINTS: [u16; 7] =
    [1_250, 2_500, 3_750, 5_000, 6_250, 7_500, 8_750];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EditKind {
    Insert,
    Delete,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryAnchor {
    ByteBefore,
    AtBoundary,
    ByteAfter,
}

#[derive(Debug, Serialize)]
pub struct StabilityResult {
    pub candidate: String,
    pub fixture_bytes: u64,
    pub base_chunks: u64,
    pub summary: StabilitySummary,
    pub cases: Vec<EditResult>,
}

#[derive(Debug, Serialize)]
pub struct StabilitySummary {
    pub neighborhoods_sampled: u64,
    pub cases: u64,
    pub cases_without_resynchronization: u64,
    pub minimum_boundary_survival_basis_points: u64,
    pub resynchronization_bytes: Option<ResynchronizationDistribution>,
}

#[derive(Debug, Serialize)]
pub struct ResynchronizationDistribution {
    pub minimum: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub maximum: u64,
}

#[derive(Debug, Serialize)]
pub struct EditResult {
    pub fixture_quantile_basis_points: u16,
    pub kind: EditKind,
    pub anchor: BoundaryAnchor,
    pub edit_offset: u64,
    pub edit_bytes: u64,
    pub boundaries_considered: u64,
    pub boundaries_survived: u64,
    pub boundary_survival_basis_points: u64,
    pub identical_chunks_reused: u64,
    pub new_chunks: u64,
    pub resynchronization_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Chunk {
    start: usize,
    end: usize,
    digest: [u8; 32],
}

#[derive(Clone, Copy)]
struct Edit {
    kind: EditKind,
    old_start: usize,
    old_end: usize,
    new_end: usize,
}

pub fn measure(candidate: &Candidate) -> Result<StabilityResult> {
    let base = pseudorandom_bytes(FIXTURE_BYTES, 0x243f_6a88_85a3_08d3);
    measure_fixture(candidate, &base, &NEIGHBORHOOD_QUANTILES_BASIS_POINTS)
}

fn measure_fixture(
    candidate: &Candidate,
    base: &[u8],
    quantiles_basis_points: &[u16],
) -> Result<StabilityResult> {
    let original = collect(candidate, base)?;
    let neighborhoods = sampled_boundaries(&original, quantiles_basis_points)?;
    let mut cases = Vec::new();
    for (quantile, center) in &neighborhoods {
        for (anchor, offset) in [
            (BoundaryAnchor::ByteBefore, center.saturating_sub(1)),
            (BoundaryAnchor::AtBoundary, *center),
            (
                BoundaryAnchor::ByteAfter,
                center
                    .checked_add(1)
                    .expect("the fixture boundary is bounded"),
            ),
        ] {
            for kind in [EditKind::Insert, EditKind::Delete, EditKind::Replace] {
                let (edited, edit) = apply_edit(base, offset, kind);
                cases.push(compare(
                    &original,
                    &collect(candidate, &edited)?,
                    edit,
                    *quantile,
                    kind,
                    anchor,
                )?);
            }
        }
    }
    let summary = summarize(&cases, neighborhoods.len())?;
    Ok(StabilityResult {
        candidate: candidate.name.clone(),
        fixture_bytes: u64::try_from(base.len())?,
        base_chunks: u64::try_from(original.len())?,
        summary,
        cases,
    })
}

fn sampled_boundaries(
    original: &[Chunk],
    quantiles_basis_points: &[u16],
) -> Result<Vec<(u16, usize)>> {
    let interior = original
        .get(..original.len().saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("stability fixture has no interior boundary"))?;
    if interior.is_empty() {
        bail!("stability fixture has no interior boundary");
    }
    let mut sampled = Vec::with_capacity(quantiles_basis_points.len());
    let mut previous_index = None;
    for quantile in quantiles_basis_points {
        if *quantile == 0 || *quantile >= 10_000 {
            bail!("stability quantiles must lie strictly between zero and 10,000");
        }
        let index = usize::try_from(
            u64::try_from(interior.len())?
                .checked_mul(u64::from(*quantile))
                .and_then(|value| value.checked_div(10_000))
                .ok_or_else(|| anyhow::anyhow!("stability quantile overflow"))?,
        )?
        .min(
            interior
                .len()
                .checked_sub(1)
                .expect("the empty interior returned above"),
        );
        if previous_index == Some(index) {
            bail!("stability quantiles select duplicate boundary neighborhoods");
        }
        previous_index = Some(index);
        sampled.push((*quantile, interior[index].end));
    }
    Ok(sampled)
}

fn collect(candidate: &Candidate, bytes: &[u8]) -> Result<Vec<Chunk>> {
    let mut chunks = Vec::new();
    let mut offset = 0_usize;
    candidate.visit_boundary_chunks(Cursor::new(bytes), |chunk| {
        let start = offset;
        offset = offset
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("chunk offset overflow"))?;
        chunks.push(Chunk {
            start,
            end: offset,
            digest: *blake3::hash(chunk).as_bytes(),
        });
        Ok(())
    })?;
    Ok(chunks)
}

fn apply_edit(base: &[u8], offset: usize, kind: EditKind) -> (Vec<u8>, Edit) {
    let marker = pseudorandom_bytes(EDIT_BYTES, 0x1319_8a2e_0370_7344);
    let mut edited = base.to_vec();
    match kind {
        EditKind::Insert => {
            edited.splice(offset..offset, marker);
            (
                edited,
                Edit {
                    kind,
                    old_start: offset,
                    old_end: offset,
                    new_end: offset
                        .checked_add(EDIT_BYTES)
                        .expect("the fixed edit fits the fixture"),
                },
            )
        },
        EditKind::Delete => {
            let end = offset
                .checked_add(EDIT_BYTES)
                .unwrap_or(edited.len())
                .min(edited.len());
            edited.drain(offset..end);
            (
                edited,
                Edit {
                    kind,
                    old_start: offset,
                    old_end: end,
                    new_end: offset,
                },
            )
        },
        EditKind::Replace => {
            let end = offset
                .checked_add(EDIT_BYTES)
                .unwrap_or(edited.len())
                .min(edited.len());
            let replacement_len = end
                .checked_sub(offset)
                .expect("the edit end does not precede its start");
            edited.splice(offset..end, marker[..replacement_len].iter().copied());
            (
                edited,
                Edit {
                    kind,
                    old_start: offset,
                    old_end: end,
                    new_end: end,
                },
            )
        },
    }
}

fn compare(
    original: &[Chunk],
    edited: &[Chunk],
    edit: Edit,
    fixture_quantile_basis_points: u16,
    kind: EditKind,
    anchor: BoundaryAnchor,
) -> Result<EditResult> {
    let old_boundaries = original
        .iter()
        .map(|chunk| chunk.end)
        .filter(|boundary| !inside_old_edit(*boundary, edit))
        .collect::<HashSet<_>>();
    let mapped_boundaries = edited
        .iter()
        .filter_map(|chunk| map_new_to_old(chunk.end, edit))
        .collect::<HashSet<_>>();
    let boundaries_survived = old_boundaries.intersection(&mapped_boundaries).count();

    let old_chunks = original.iter().cloned().collect::<HashSet<_>>();
    let mut identical_chunks_reused = 0_usize;
    let mut first_resynchronized_start = None;
    for chunk in edited {
        let Some(start) = map_new_to_old(chunk.start, edit) else {
            continue;
        };
        let Some(end) = map_new_to_old(chunk.end, edit) else {
            continue;
        };
        let mapped = Chunk {
            start,
            end,
            digest: chunk.digest,
        };
        if old_chunks.contains(&mapped) {
            identical_chunks_reused = identical_chunks_reused
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("identical chunk count overflow"))?;
            if chunk.start >= edit.new_end && first_resynchronized_start.is_none() {
                first_resynchronized_start = Some(chunk.start);
            }
        }
    }

    let considered = u64::try_from(old_boundaries.len())?;
    let survived = u64::try_from(boundaries_survived)?;
    let survival_basis_points = if considered == 0 {
        0
    } else {
        survived
            .checked_mul(10_000)
            .and_then(|value| value.checked_div(considered))
            .ok_or_else(|| anyhow::anyhow!("boundary survival overflow"))?
    };
    Ok(EditResult {
        fixture_quantile_basis_points,
        kind,
        anchor,
        edit_offset: u64::try_from(edit.old_start)?,
        edit_bytes: u64::try_from(edit.old_end.saturating_sub(edit.old_start).max(EDIT_BYTES))?,
        boundaries_considered: considered,
        boundaries_survived: survived,
        boundary_survival_basis_points: survival_basis_points,
        identical_chunks_reused: u64::try_from(identical_chunks_reused)?,
        new_chunks: u64::try_from(edited.len().saturating_sub(identical_chunks_reused))?,
        resynchronization_bytes: first_resynchronized_start
            .map(|start| u64::try_from(start.saturating_sub(edit.new_end)))
            .transpose()?,
    })
}

fn summarize(cases: &[EditResult], neighborhoods: usize) -> Result<StabilitySummary> {
    if cases.is_empty() {
        bail!("stability measurement produced no edit cases");
    }
    let minimum_boundary_survival_basis_points = cases
        .iter()
        .map(|case| case.boundary_survival_basis_points)
        .min()
        .expect("the non-empty case set has a minimum");
    let cases_without_resynchronization = cases
        .iter()
        .filter(|case| case.resynchronization_bytes.is_none())
        .count();
    let mut distances = cases
        .iter()
        .filter_map(|case| case.resynchronization_bytes)
        .collect::<Vec<_>>();
    distances.sort_unstable();
    let resynchronization_bytes = if distances.is_empty() {
        None
    } else {
        Some(ResynchronizationDistribution {
            minimum: distances[0],
            p50: percentile(&distances, 50)?,
            p95: percentile(&distances, 95)?,
            p99: percentile(&distances, 99)?,
            maximum: *distances
                .last()
                .expect("the non-empty distance set has a maximum"),
        })
    };
    Ok(StabilitySummary {
        neighborhoods_sampled: u64::try_from(neighborhoods)?,
        cases: u64::try_from(cases.len())?,
        cases_without_resynchronization: u64::try_from(cases_without_resynchronization)?,
        minimum_boundary_survival_basis_points,
        resynchronization_bytes,
    })
}

fn percentile(sorted: &[u64], percentile: u64) -> Result<u64> {
    let last = u64::try_from(sorted.len().saturating_sub(1))?;
    let index = last
        .checked_mul(percentile)
        .and_then(|value| value.checked_add(99))
        .and_then(|value| value.checked_div(100))
        .ok_or_else(|| anyhow::anyhow!("stability percentile overflow"))?;
    sorted
        .get(usize::try_from(index)?)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("stability percentile is outside the distribution"))
}

fn inside_old_edit(boundary: usize, edit: Edit) -> bool {
    edit.old_start < edit.old_end && (edit.old_start..edit.old_end).contains(&boundary)
}

fn map_new_to_old(position: usize, edit: Edit) -> Option<usize> {
    match edit.kind {
        EditKind::Insert => {
            let inserted = edit
                .new_end
                .checked_sub(edit.old_start)
                .expect("insert end follows insert start");
            if position <= edit.old_start {
                Some(position)
            } else if position >= edit.new_end {
                position.checked_sub(inserted)
            } else {
                None
            }
        },
        EditKind::Delete => {
            let deleted = edit
                .old_end
                .checked_sub(edit.old_start)
                .expect("delete end follows delete start");
            if position <= edit.old_start {
                Some(position)
            } else {
                position.checked_add(deleted)
            }
        },
        EditKind::Replace => Some(position),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::candidates;

    #[test]
    fn local_edits_resynchronize_for_every_candidate() {
        let fixture = pseudorandom_bytes(1024 * 1024, 0x243f_6a88_85a3_08d3);
        let quantiles = [2_500, 5_000, 7_500];
        for candidate in candidates(8).unwrap() {
            let result = measure_fixture(&candidate, &fixture, &quantiles).unwrap();
            assert_eq!(result.cases.len(), quantiles.len() * 9);
            assert_eq!(
                result.summary.neighborhoods_sampled,
                u64::try_from(quantiles.len()).unwrap()
            );
            assert_eq!(result.summary.cases_without_resynchronization, 0);
            for case in result.cases {
                assert!(
                    case.resynchronization_bytes.is_some(),
                    "{} {:?} {:?}",
                    candidate.name,
                    case.kind,
                    case.anchor
                );
                assert!(case.boundary_survival_basis_points > 9_000);
            }
        }
    }

    #[test]
    fn coordinate_mapping_excludes_inserted_bytes() {
        let edit = Edit {
            kind: EditKind::Insert,
            old_start: 10,
            old_end: 10,
            new_end: 15,
        };
        assert_eq!(map_new_to_old(10, edit), Some(10));
        assert_eq!(map_new_to_old(11, edit), None);
        assert_eq!(map_new_to_old(15, edit), Some(10));
        assert_eq!(map_new_to_old(20, edit), Some(15));
    }

    #[test]
    fn neighborhood_sampling_rejects_duplicate_quantiles() {
        let chunks = (1..=4)
            .map(|index| Chunk {
                start: (index - 1) * 100,
                end: index * 100,
                digest: [0; 32],
            })
            .collect::<Vec<_>>();
        assert!(sampled_boundaries(&chunks, &[1, 2]).is_err());
    }
}
