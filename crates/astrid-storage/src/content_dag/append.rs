use std::collections::{BTreeMap, BTreeSet};

use super::build::{append_chunks, build_tree, file_record};
use super::read::traversal::verified_chunks;
use super::{
    ContentDescriptor, ContentError, ContentReadError, ContentSource, OpenedContent,
    VerifiedContent, insert_record, read_verified_content_range,
};
use crate::storage_model::{ObjectIdentity, ObjectRecord};

/// A delta, not a complete closure: unchanged objects remain in the pinned source.
pub(crate) struct AppendedContent {
    pub(crate) verified: VerifiedContent,
    pub(crate) records: Vec<ObjectRecord>,
}

/// Rechunk only the old EOF chunk and appended bytes, retaining canonical identity.
///
/// All preceding boundaries are final because the input carries a full verification
/// proof. Metadata is rebuilt canonically; this is O(chunk count) metadata work, not
/// a right-spine-only update. The caller must pin the old closure through publication.
pub(crate) fn append_verified_content<I: ObjectIdentity, S: ContentSource>(
    identity: &I,
    source: &S,
    old: VerifiedContent,
    bytes: &[u8],
) -> Result<AppendedContent, ContentReadError<S::Error>> {
    let descriptor = old.descriptor();
    let logical_bytes = descriptor
        .logical_bytes()
        .checked_add(u64::try_from(bytes.len()).map_err(|_| ContentError::LengthOverflow)?)
        .ok_or(ContentError::LengthOverflow)?;
    let mut chunks = verified_chunks(source, old)?;
    let mut tail = if let Some(last) = chunks.pop() {
        read_verified_content_range(
            source,
            old,
            descriptor
                .logical_bytes()
                .checked_sub(last.logical_bytes)
                .ok_or(ContentError::LengthOverflow)?,
            last.logical_bytes,
        )?
    } else {
        Vec::new()
    };
    tail.try_reserve(bytes.len())
        .map_err(|_| ContentError::LengthOverflow)?;
    tail.extend_from_slice(bytes);
    let mut records = BTreeMap::new();
    // The whole-file small-value exception is not a small-tail exception.
    append_chunks(
        identity,
        descriptor.profile(),
        &tail,
        logical_bytes <= u64::from(descriptor.profile().maximum_bytes()),
        &mut records,
        &mut chunks,
        &mut BTreeSet::new(),
    )?;
    let chunk_count = u64::try_from(chunks.len()).map_err(|_| ContentError::LengthOverflow)?;
    let content = build_tree(identity, &mut records, chunks)?;
    let file = file_record(descriptor.profile(), logical_bytes, chunk_count, content)?;
    let file = insert_record(identity, &mut records, file)?;
    Ok(AppendedContent {
        verified: VerifiedContent::new(OpenedContent::new(
            ContentDescriptor::new(file, logical_bytes, chunk_count, descriptor.profile()),
            content.map(|child| child.id),
        )),
        records: records.into_values().collect(),
    })
}

#[cfg(test)]
mod tests;
