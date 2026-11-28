//! Bytewise ordering for persisted owner names and storage keys.
use std::cmp::Ordering;
use vstd::prelude::*;

verus! {
/// Unsigned bytewise lexicographic order, with a shorter matching prefix first.
pub(crate) open spec fn below(a: Seq<u8>, b: Seq<u8>) -> bool
    decreases b.len(),
{
    if b.len() == 0 { false }
    else if a.len() == 0 { true }
    else { a[0] < b[0] || (a[0] == b[0] && below(a.skip(1), b.skip(1))) }
}

/// Compare persisted byte keys in unsigned lexicographic order.
#[inline]
pub(crate) fn bytewise_cmp(left: &[u8], right: &[u8]) -> (order: Ordering)
    ensures
        (order == Ordering::Less) == below(left@, right@),
        (order == Ordering::Equal) == (left@ == right@),

{
    assert(left@.skip(0) =~= left@);
    assert(right@.skip(0) =~= right@);
    let mut i = 0usize;
    while i < left.len() && i < right.len()
        invariant
            i <= left.len() && i <= right.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] left@[j] == right@[j],
            below(left@, right@) == below(left@.skip(i as int), right@.skip(i as int)),
        decreases left.len() - i,
    {
        let a = left[i];
        let b = right[i];
        if a != b { return a.cmp(&b); }
        assert(left@.skip(i as int).skip(1) =~= left@.skip(i as int + 1));
        assert(right@.skip(i as int).skip(1) =~= right@.skip(i as int + 1));
        i = i.saturating_add(1);
    }
    if left.len() == right.len() { assert(left@ =~= right@); }
    left.len().cmp(&right.len())
}

#[inline]
pub(crate) fn bytewise_less(left: &[u8], right: &[u8]) -> (less: bool)
    ensures less == below(left@, right@),
{
    matches!(bytewise_cmp(left, right), Ordering::Less)
}

}
