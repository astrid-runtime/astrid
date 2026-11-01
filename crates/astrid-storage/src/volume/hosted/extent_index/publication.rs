//! Prepare immutable metadata before publishing its single ASTREG1 commit.

use std::{collections::BTreeMap, io};

use super::super::{
    CheckpointFormat, ContainerState, FlushState, IndexCheckpoint, RegionState, VolumeRegion,
};
use super::checkpoint::{self, RegionRoot};
use super::codec::IndexedExtent;
use super::records::{RecordReader, append_page};
use super::reference::{RecordOffset, RecordSequence};
use super::update::rewrite_tree;

pub(in crate::volume::hosted) fn prepare_checkpoint(
    state: &mut ContainerState,
) -> io::Result<Vec<u8>> {
    let start = state.valid_len;
    let sequence = state.sequence;
    let file = state.file.try_clone()?;
    let reader = RecordReader {
        file: &file,
        published_before: RecordOffset::new(start)?,
        commit_sequence: next_sequence(sequence)?,
    };
    // The state lock excludes readers. Keep the original namespace intact
    // until every replacement tree exists, so any preparation error can drop
    // only this unpublished metadata suffix and retry from the same data.
    let mut regions = std::mem::take(&mut state.regions);
    let prepared = regions
        .values()
        .map(|region| {
            let pending = region.extents.iter().map(|(start, extent)| {
                IndexedExtent::new(*start, extent.logical_end, extent.physical_offset)
            });
            rewrite_tree(
                &reader,
                region.root,
                region.base_limit,
                pending,
                &mut |page| append_page(state, page),
            )
        })
        .collect::<io::Result<Vec<_>>>();
    // Validate the catalogue before replacing any in-memory ownership. A late
    // encoding/sequence failure has the same rollback as a failed page append.
    let prepared = prepared
        .and_then(|roots| encode_prepared(state, &regions, &roots).map(|payload| (roots, payload)));
    match prepared {
        Ok((roots, payload)) => {
            for (region, root) in regions.values_mut().zip(roots) {
                region.root = root;
                region.base_limit = region.length;
                region.extents.clear();
            }
            state.regions = regions;
            state.checkpoint_format = CheckpointFormat::Paged;
            state.index_checkpoint = IndexCheckpoint::Prepared;
            state.flush_state = FlushState::Required;
            Ok(payload)
        },
        Err(error) => {
            state.regions = regions;
            state.valid_len = start;
            state.sequence = sequence;
            // Append marks footer_pending before touching the file, even if
            // its first write fails. Without that mutation, preserve the
            // existing footer and its confirmed flush proof.
            if state.footer_pending {
                // No commit has been written, so only unpublished bytes are
                // removed. Later appends/footer writes retry a failed truncate.
                state.file.set_len(start).map_err(|rollback| {
                    io::Error::other(format!(
                        "extent-index preparation failed: {error}; suffix rollback failed: {rollback}"
                    ))
                })?;
            }
            Err(error)
        },
    }
}

fn encode_prepared(
    state: &ContainerState,
    regions: &BTreeMap<VolumeRegion, RegionState>,
    roots: &[Option<super::reference::PageRef>],
) -> io::Result<Vec<u8>> {
    let offset = RecordOffset::new(state.valid_len)?;
    let sequence = next_sequence(state.sequence)?;
    let catalogue = regions
        .iter()
        .zip(roots)
        .map(|((name, region), root)| {
            RegionRoot::new(region.length, *root, offset, sequence).map(|root| (name.clone(), root))
        })
        .collect::<io::Result<_>>()?;
    checkpoint::encode(&catalogue, offset, sequence)
}

fn next_sequence(sequence: u64) -> io::Result<RecordSequence> {
    RecordSequence::new(
        sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Astrid volume sequence exhausted"))?,
    )
}
