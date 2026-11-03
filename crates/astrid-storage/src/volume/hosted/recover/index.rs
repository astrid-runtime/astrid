//! Extent-page record validation shares ASTREG1 framing and checksums.

use super::super::extent_index::{
    INDEX_PAGE_REGION,
    codec::{PAGE_BYTES, Page},
    reference::{PageRef, RecordOffset, RecordSequence},
};
use super::super::extent_index::{checkpoint, records::RecordReader, traversal};
use super::{
    BTreeMap, CheckpointFormat, File, Operation, RECORD_FIXED_BYTES, RecordHeader, RegionState,
    VolumeRegion, decode_region_snapshot, invalid_transition, io, read_header, read_record_payload,
};

pub(super) fn checkpoint_format(payload: &[u8]) -> CheckpointFormat {
    if payload.starts_with(&checkpoint::CHECKPOINT_MAGIC) {
        CheckpointFormat::Paged
    } else {
        CheckpointFormat::Legacy
    }
}

pub(super) fn decode_checkpoint(
    file: &File,
    payload: &[u8],
    offset: u64,
    sequence: u64,
) -> io::Result<BTreeMap<VolumeRegion, RegionState>> {
    if checkpoint_format(payload) == CheckpointFormat::Legacy {
        return decode_region_snapshot(payload, offset);
    }
    let offset = RecordOffset::new(offset)?;
    let sequence = RecordSequence::new(sequence)?;
    let catalogue = checkpoint::decode(payload, offset, sequence)?;
    let reader = RecordReader {
        file,
        published_before: offset,
        commit_sequence: sequence,
    };
    let mut regions = BTreeMap::new();
    for (name, region) in catalogue {
        if let Some(root) = region.root() {
            traversal::verify_tree(&reader, root)?;
        }
        regions.insert(
            name,
            RegionState {
                length: region.length(),
                root: region.root(),
                base_limit: region.length(),
                extents: BTreeMap::new(),
            },
        );
    }
    Ok(regions)
}

pub(in crate::volume::hosted) fn read_index_page(
    file: &File,
    reference: PageRef,
    published_before: RecordOffset,
    commit_sequence: RecordSequence,
) -> io::Result<Page> {
    reference.require_before(published_before, commit_sequence)?;
    let header = read_header(file, reference.offset().get(), published_before.get())?
        .ok_or_else(|| invalid_transition("truncated extent-index record"))?;
    if header.sequence != reference.sequence().get() || header.checksum != *reference.checksum() {
        return Err(invalid_transition("extent-index record identity mismatch"));
    }
    require_envelope(&header)?;
    let payload = read_record_payload(file, &header)?;
    let page = validate_index_page(&header, payload.as_deref())?;
    page.validate_reference(reference)?;
    Ok(page)
}

pub(super) fn validate_index_page(
    header: &RecordHeader,
    payload: Option<&[u8]>,
) -> io::Result<Page> {
    require_envelope(header)?;
    let payload = payload.ok_or_else(|| invalid_transition("missing extent-index page payload"))?;
    let page = Page::decode(payload)?;
    let offset = header
        .payload_offset
        .checked_sub(RECORD_FIXED_BYTES as u64)
        .and_then(|offset| offset.checked_sub(header.name.as_str().len() as u64))
        .ok_or_else(|| invalid_transition("extent-index record position underflow"))?;
    page.reference(
        RecordOffset::new(offset)?,
        RecordSequence::new(header.sequence)?,
        header.checksum,
    )?;
    Ok(page)
}

fn require_envelope(header: &RecordHeader) -> io::Result<()> {
    if header.operation != Operation::IndexPage
        || header.name.as_str() != INDEX_PAGE_REGION
        || header.logical_offset != 0
        || header.payload_len != PAGE_BYTES as u64
    {
        return Err(invalid_transition("invalid extent-index record envelope"));
    }
    Ok(())
}
