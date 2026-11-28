//! Canonical label lookup shared by content headers and KV delta recovery.
#[cfg(verus_keep_ghost)]
use super::ObjectRecord;
use super::ObjectReference;
use vstd::prelude::*;

verus! {
/// A label in its canonical binary-search position.
pub(crate) open spec fn positioned(refs:Seq<ObjectReference>,label:Seq<u8>,i:int) -> bool {
    &&& 0 <= i < refs.len()
    &&& refs[i].fields().0 == label
    &&& forall|j:int| 0 <= j < i ==> #[trigger] refs[j].fields().0 != label && ObjectRecord::label_before(refs[j].fields().0,label)
    &&& forall|j:int| i < j < refs.len() ==> #[trigger] refs[j].fields().0 != label && !ObjectRecord::label_before(refs[j].fields().0,label)
}

/// The exact reference selected by the decoder, even for noncanonical input.
pub(crate) open spec fn selected(refs: Seq<ObjectReference>, label: Seq<u8>, lo: int, hi: int)
    -> Option<ObjectReference>
    decreases hi - lo,
{
    if lo < 0 || lo >= hi || hi > refs.len() {
        None
    } else {
        let mid = lo + (hi - lo) / 2;
        let r = refs[mid];
        if r.fields().0 == label { Some(r) }
        else if ObjectRecord::label_before(r.fields().0, label) { selected(refs, label, mid + 1, hi) }
        else { selected(refs, label, lo, mid) }
    }
}

/// In a canonical record, the row bearing a label is the one the binary search returns.
pub(crate) proof fn canonical_row(refs:Seq<ObjectReference>,i:int,lo:int,hi:int)
    requires ObjectRecord::labels_ordered(refs),0 <= lo <= i < hi <= refs.len(),
    ensures selected(refs,refs[i].fields().0,lo,hi) == Some(refs[i]),
    decreases hi-lo,
{
    let mid = lo+(hi-lo)/2;
    if mid < i {
        ObjectRecord::ordered_pair(refs,mid,i);
        canonical_row(refs,i,mid+1,hi);
    } else if mid > i {
        ObjectRecord::ordered_pair(refs,i,mid);
        canonical_row(refs,i,lo,mid);
    }
}

pub(crate) fn find<'a>(refs:&'a [ObjectReference],label:&[u8]) -> (out:Option<&'a ObjectReference>)
    ensures (match out { Some(r) => Some(*r), None => None }) == selected(refs@,label@,0,refs.len() as int),
        out matches Some(r) ==> refs@.contains(*r) && r.fields().0 == label@,
        forall|i:int| #[trigger] positioned(refs@,label@,i) ==> (out matches Some(r) && *r == refs@[i]),
{
    let mut lo = 0usize;
    let mut hi = refs.len();
    while lo < hi
        invariant lo <= hi <= refs.len(),
            selected(refs@,label@,lo as int,hi as int) == selected(refs@,label@,0,refs.len() as int),
            forall|i:int| #[trigger] positioned(refs@,label@,i) ==> lo <= i < hi,
        decreases hi-lo,
    {
        let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
        let r = &refs[mid];
        if r.label_bytes() == label {
            assert(r.fields().0 =~= label@);
            assert(refs@[mid as int] == *r);
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies i == mid by {
                if i != mid { assert(refs@[mid as int].fields().0 != label@); }
            }
            return Some(r);
        }
        assert(r.fields().0 != label@);
        if r.label_less_than(label) {
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies mid < i by {
                if i < mid { assert(!ObjectRecord::label_before(refs@[mid as int].fields().0,label@)); }
            }
            lo = mid.saturating_add(1);
        } else {
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies i < mid by {
                if mid < i { assert(ObjectRecord::label_before(refs@[mid as int].fields().0,label@)); }
            }
            hi = mid;
        }
    }
    None
}

}
