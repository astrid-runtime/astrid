//! Account for physical copies that have no separate row in the object index.
use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, DurableIo, FRAME_HEADER_LEN, IdentityScheme,
    ObjectId, RecoveryLimits, SliceReader, read_frame_preserving_cursor_within,
};

pub(in crate::engine::durable) fn duplicate_range(
    arena: &mut impl DurableIo,
    objects: &BTreeMap<ObjectId, ArenaLocation>,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
    mut cursor: u64,
    end: u64,
) -> bool {
    while cursor < end {
        let Ok(copy) = read_frame_preserving_cursor_within(
            arena,
            ARENA_FILE,
            ARENA_MAGIC,
            cursor,
            limits,
            end,
        ) else {
            return false;
        };
        let Ok(id) = SliceReader::new(&copy).identity(scheme) else {
            return false;
        };
        let Some(first) = objects.get(&id) else {
            return false;
        };
        let Ok(length) = u64::try_from(copy.len()) else {
            return false;
        };
        if first.offset >= cursor || first.payload_len != length {
            return false;
        }
        // The indexed occurrence must already have been visited. Compare both
        // checksum-validated payloads so a conflicting duplicate forces a scan.
        let Ok(original) = read_frame_preserving_cursor_within(
            arena,
            ARENA_FILE,
            ARENA_MAGIC,
            first.offset,
            limits,
            cursor,
        ) else {
            return false;
        };
        if original != copy {
            return false;
        }
        let Some(next) = cursor
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|at| at.checked_add(length))
        else {
            return false;
        };
        cursor = next;
    }
    cursor == end
}
