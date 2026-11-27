//! The branch fence and the child summary occupy consecutive, unambiguous fields.
use crate::{checkpoint_key_field as key, checkpoint_totals::NodeTotals, storage_words::word32};
use vstd::prelude::*;

verus! {
fn branch_fields(bytes: &mut Vec<u8>, fence: &[u8], totals: NodeTotals, suffix: &[u8])
    -> (end: usize)
    requires fence.len() <= u32::MAX,
        old(bytes).len() as int + 4 + fence.len() + 24 + suffix.len() <= usize::MAX,
    ensures end as int == old(bytes).len() + 4 + fence.len() + 24,
{
    let mut cursor = bytes.len();
    let ghost start = cursor as int;
    let wrote = key::append(bytes,fence);
    assert(wrote);
    totals.append(bytes);
    bytes.extend_from_slice(suffix);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(totals.wire().len() == 24);
        assert(bytes@.subrange(start,start+4) =~= word32(fence.len() as u32));
        key::encoded_length(bytes@,start,fence.len() as u32);
        assert(bytes@.subrange(start+4,start+4+fence.len()) =~= fence@);
    }
    let decoded = key::read(bytes,&mut cursor);
    assert(decoded matches Ok(field) && field@ == fence@);
    let summary = NodeTotals::read(bytes,&mut cursor);
    assert(summary.is_ok());
    assert(bytes@.subrange(start+4+fence.len(),start+4+fence.len()+24) =~= totals.wire());
    assert(summary->Ok_0.wire() == totals.wire());
    cursor
}

fn incomplete(bytes: &[u8], start: usize) -> (rejected: bool)
    requires start as int + 4 > bytes.len() ||
        start as int + 4 + key::length(bytes@,start as int) > bytes.len(),
    ensures rejected,
{
    let mut cursor = start;
    key::read(bytes,&mut cursor).is_err()
}
}
