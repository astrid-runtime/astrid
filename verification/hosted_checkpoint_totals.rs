//! A page writer and reader agree at an arbitrary position in the record.
use crate::{checkpoint_totals::NodeTotals, storage_fields::{at, ReadError}};
use vstd::prelude::*;

verus! {

fn round_trip(bytes: &mut Vec<u8>, totals: NodeTotals, tail: &[u8])
    -> (out: Result<NodeTotals,ReadError>)
    requires old(bytes).len() as int + 24 + tail.len() <= usize::MAX,
    ensures out == Ok(totals), final(bytes)@ == old(bytes)@ + totals.wire() + tail@,
{
    let mut pos = bytes.len();
    let ghost start = pos as int;
    totals.append(bytes);
    bytes.extend_from_slice(tail);
    let out = NodeTotals::read(bytes,&mut pos);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(totals.wire().len() == 24);
        assert(at(bytes@,start,totals.wire())) by {
            assert(bytes@.subrange(start,start+24) =~= totals.wire());
        }
        if let Ok(t) = out {
            assert(t.wire() == totals.wire());
            assert(t.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(t.entries));
            assert(t.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(t.logical_bytes));
            assert(t.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(t.quota_bytes));
            assert(totals.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(totals.entries));
            assert(totals.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(totals.logical_bytes));
            assert(totals.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(totals.quota_bytes));
        }
    }
    out
}

fn truncated(bytes: &[u8], start: usize) -> (rejected: bool)
    requires start as int + 24 > bytes.len(),
    ensures rejected,
{
    let mut pos = start;
    NodeTotals::read(bytes,&mut pos).is_err()
}
}
