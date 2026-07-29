use std::collections::HashSet;
use std::io::Cursor;

use anyhow::Result;
use serde::Serialize;

use crate::algorithm::Candidate;
use crate::fixture::pseudorandom_bytes;

const FIXTURE_BYTES: usize = 8 * 1024 * 1024;
const EDIT_BYTES: usize = 257;

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
    pub cases: Vec<EditResult>,
}

#[derive(Debug, Serialize)]
pub struct EditResult {
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
    let original = collect(candidate, &base)?;
    let center = original
        .get(original.len() / 2)
        .map(|chunk| chunk.end)
        .expect("the stability fixture always produces chunks");
    let mut cases = Vec::new();
    for (anchor, offset) in [
        (BoundaryAnchor::ByteBefore, center.saturating_sub(1)),
        (BoundaryAnchor::AtBoundary, center),
        (
            BoundaryAnchor::ByteAfter,
            center
                .checked_add(1)
                .expect("the fixture center is bounded"),
        ),
    ] {
        for kind in [EditKind::Insert, EditKind::Delete, EditKind::Replace] {
            let (edited, edit) = apply_edit(&base, offset, kind);
            cases.push(compare(
                &original,
                &collect(candidate, &edited)?,
                edit,
                kind,
                anchor,
            )?);
        }
    }
    Ok(StabilityResult {
        candidate: candidate.name.clone(),
        fixture_bytes: u64::try_from(base.len())?,
        base_chunks: u64::try_from(original.len())?,
        cases,
    })
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
        for candidate in candidates(8).unwrap() {
            let result = measure(&candidate).unwrap();
            assert_eq!(result.cases.len(), 9);
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
}
