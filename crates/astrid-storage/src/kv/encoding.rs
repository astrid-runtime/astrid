//! Canonical durable KV entry addresses.

#[cfg(verus_keep_ghost)]
pub(super) use crate::byte_order::below;
pub(super) use crate::byte_order::{bytewise_cmp, bytewise_less};
use vstd::prelude::*;

verus! {

pub(super) fn composite(namespace: &[u8], key: &[u8]) -> (address: Vec<u8>)
    ensures address@ == namespace@ + seq![0u8] + key@,
{
    let mut address = Vec::with_capacity(namespace.len().saturating_add(1).saturating_add(key.len()));
    address.extend_from_slice(namespace);
    address.push(0);
    address.extend_from_slice(key);
    address
}

/// The pivot is the last byte with a successor. Remove maximal trailing
/// bytes and increment that pivot to obtain the exclusive upper bound.
pub(super) open spec fn successor_at(start: Seq<u8>, end: Seq<u8>, pivot: int) -> bool {
    &&& 0 <= pivot < start.len()
    &&& end.len() == pivot + 1
    &&& end.take(pivot) == start.take(pivot)
    &&& end[pivot] as int == start[pivot] as int + 1
    &&& forall|i: int| pivot < i < start.len() ==> #[trigger] start[i] == 255
}

pub(super) open spec fn range_contains(start: Seq<u8>, end: Seq<u8>, key: Seq<u8>) -> bool {
    !below(key, start) && below(key, end)
}

pub(super) open spec fn exact_interval(start: Seq<u8>, end: Seq<u8>) -> bool {
    forall|key: Seq<u8>| { #[trigger] range_contains(start, end, key) == matches_prefix(key, start) }
}

pub(super) fn prefix_end(namespace: &[u8], prefix: &[u8]) -> (end: Vec<u8>)
    ensures exact_interval(namespace@ + seq![0u8] + prefix@, end@),
        prefix.len() == 0 ==> end@ == namespace@ + seq![1u8],
{
    let mut end = composite(namespace, prefix);
    let ghost start = end@;
    let ghost separator = namespace.len();
    assert(start[separator as int] == 0);
    loop
        invariant
            start == namespace@ + seq![0u8] + prefix@,
            separator == namespace.len(), separator < end.len() <= start.len(),
            start[separator as int] == 0,
            end@ == start.take(end.len() as int),
            forall|i: int| end.len() <= i < start.len() ==> #[trigger] start[i] == 255,
        decreases end.len(),
    {
        let pivot = end.len().saturating_sub(1);
        let byte = end[pivot];
        if byte < 255 {
            end[pivot] = byte.saturating_add(1);
            assert(end@.take(pivot as int) =~= start.take(pivot as int));
            assert(successor_at(start, end@, pivot as int));
            proof {
                all_prefix_interval(start, end@, pivot as int);
                if prefix.len() == 0 {
                    assert(pivot == separator);
                    assert(end@ =~= namespace@ + seq![1u8]);
                }
            }
            return end;
        }
        end.pop();
        assert(end@ =~= start.take(end.len() as int));
    }
}

#[inline]
pub(super) fn entry_in_range(key: &[u8], start: &[u8], end: &[u8]) -> (selected: bool)
    ensures selected == range_contains(start@, end@, key@),
{
    !bytewise_less(key, start) && bytewise_less(key, end)
}

proof fn ordered_split(a: Seq<u8>, middle: Seq<u8>, b: Seq<u8>)
    requires below(a, b),
    ensures below(a, middle) || below(middle, b),
    decreases b.len(),
{
    if a.len() > 0 && middle.len() > 0 && a[0] == b[0] && a[0] == middle[0] {
        ordered_split(a.skip(1), middle.skip(1), b.skip(1));
    }
}

/// Prune only children whose key interval cannot contain a requested entry.
/// The last child has no upper fence.
#[inline]
pub(super) fn visit_child(lower: &[u8], upper: Option<&[u8]>, start: &[u8], end: &[u8]) -> (visit: bool)
    ensures
        visit == (below(lower@, end@) && match upper { Some(u) => below(start@, u@), None => true }),
        forall|k: Seq<u8>| #[trigger] range_contains(start@, end@, k)
            && !below(k, lower@) && (match upper { Some(u) => below(k, u@), None => true })
            ==> visit,
{
    proof {
        assert forall|k: Seq<u8>| #[trigger] range_contains(start@, end@, k)
            && !below(k, lower@) && (match upper { Some(u) => below(k, u@), None => true })
            implies below(lower@, end@) && (match upper { Some(u) => below(start@, u@), None => true })
        by {
            ordered_split(k, lower@, end@);
            if let Some(u) = upper { ordered_split(k, start@, u@); }
        }
    }
    match upper {
        Some(fence) if !bytewise_less(start, fence) => false,
        _ => bytewise_less(lower, end),
    }
}

pub(super) open spec fn matches_prefix(key: Seq<u8>, prefix: Seq<u8>) -> bool {
    &&& prefix.len() <= key.len()
    &&& forall|i: int| 0 <= i < prefix.len() ==> key[i] == #[trigger] prefix[i]
}

proof fn strip_equal_head(key: Seq<u8>, prefix: Seq<u8>)
    requires key.len() > 0, prefix.len() > 0, key[0] == prefix[0],
    ensures matches_prefix(key, prefix) == matches_prefix(key.skip(1), prefix.skip(1)),
{
    if matches_prefix(key.skip(1), prefix.skip(1)) {
        assert forall|i: int| 0 <= i < prefix.len() implies key[i] == #[trigger] prefix[i] by {
            if i > 0 { assert(key.skip(1)[i-1] == prefix.skip(1)[i-1]); }
        }
    }
}

proof fn maximal_suffix(key: Seq<u8>, suffix: Seq<u8>)
    requires forall|i: int| 0 <= i < suffix.len() ==> #[trigger] suffix[i] == 255,
    ensures !below(key, suffix) == matches_prefix(key, suffix),
    decreases suffix.len(),
{
    if suffix.len() == 0 {
        assert(key.take(0) =~= suffix);
    } else if key.len() > 0 && key[0] == suffix[0] {
        strip_equal_head(key, suffix);
        maximal_suffix(key.skip(1), suffix.skip(1));
    }
}

/// The half-open interval includes exactly the physical addresses starting
/// with the complete lower-bound bytes.
pub(super) proof fn prefix_interval(start: Seq<u8>, end: Seq<u8>, pivot: int, key: Seq<u8>)
    requires successor_at(start, end, pivot),
    ensures (!below(key, start) && below(key, end)) == matches_prefix(key, start),
    decreases pivot,
{
    reveal_with_fuel(below, 2);
    if key.len() == 0 { return; }
    if pivot > 0 {
        assert(start.take(pivot)[0] == end.take(pivot)[0]);
        if key[0] == start[0] {
            strip_equal_head(key, start);
            assert(end.skip(1).take(pivot-1) =~= start.skip(1).take(pivot-1)) by {
                assert forall|i: int| 0 <= i < pivot-1 implies
                    end.skip(1)[i] == start.skip(1)[i] by {
                    assert(end.take(pivot)[i+1] == start.take(pivot)[i+1]);
                }
            }
            prefix_interval(start.skip(1), end.skip(1), pivot-1, key.skip(1));
        }
    } else if key[0] == start[0] {
        strip_equal_head(key, start);
        maximal_suffix(key.skip(1), start.skip(1));
    } else if key[0] == end[0] {
        assert(end.skip(1).len() == 0);
        assert(!below(key.skip(1), end.skip(1)));
    }
}

proof fn all_prefix_interval(start: Seq<u8>, end: Seq<u8>, pivot: int)
    requires successor_at(start, end, pivot),
    ensures exact_interval(start, end),
{
    assert forall|key: Seq<u8>| (#[trigger] range_contains(start, end, key) == matches_prefix(key, start)) by {
        prefix_interval(start, end, pivot, key);
    }

}

/// Translate physical interval membership into the guest's namespace and
/// logical key prefix. Valid namespaces cannot contain the separator.
pub(super) proof fn logical_prefix_range(
    ns: Seq<u8>, prefix: Seq<u8>, end: Seq<u8>, other: Seq<u8>, key: Seq<u8>,
)
    requires
        !ns.contains(0u8), !other.contains(0u8),
        exact_interval(ns + seq![0u8] + prefix, end),
    ensures
        range_contains(ns + seq![0u8] + prefix, end, other + seq![0u8] + key)
            == (ns == other && matches_prefix(key, prefix)),
{
    let start = ns + seq![0u8] + prefix;
    let address = other + seq![0u8] + key;
    assert(range_contains(start, end, address) == matches_prefix(address, start));
    if matches_prefix(address, start) {
        if ns.len() < other.len() {
            assert(start[ns.len() as int] == 0u8);
            assert(other[ns.len() as int] == 0u8);
            assert(other.contains(0u8));
        }
        if other.len() < ns.len() {
            assert(address[other.len() as int] == 0u8);
            assert(start[other.len() as int] == address[other.len() as int]);
            assert(ns[other.len() as int] == 0u8);
            assert(ns.contains(0u8));
        }
        assert(ns =~= other) by {
            assert forall|i: int| 0 <= i < ns.len() implies ns[i] == other[i] by {
                assert(start[i] == address[i]);
            }
        }
        assert forall|i: int| 0 <= i < prefix.len() implies key[i] == #[trigger] prefix[i] by {
            assert(start[ns.len() + 1 + i] == address[ns.len() + 1 + i]);
        }
    } else if ns == other && matches_prefix(key, prefix) {
        assert forall|i: int| 0 <= i < start.len() implies address[i] == #[trigger] start[i] by {
            if i > ns.len() { assert(key[i - ns.len() - 1] == prefix[i - ns.len() - 1]); }
        }
    }
}

/// Under namespace validation, equal physical addresses identify exactly one
/// namespace and one complete key, including when either is a prefix of another.
pub(super) proof fn address_injective(a: Seq<u8>, k: Seq<u8>, b: Seq<u8>, q: Seq<u8>)
    requires
        !a.contains(0u8),
        !b.contains(0u8),
        a + seq![0u8] + k == b + seq![0u8] + q,
    ensures a == b && k == q,
{
    if a.len() < b.len() {
        assert((a + seq![0u8] + k)[a.len() as int] == 0u8);
        assert(b[a.len() as int] == 0u8);
        assert(b.contains(0u8));
    }
    if b.len() < a.len() {
        assert((b + seq![0u8] + q)[b.len() as int] == 0u8);
        assert(a[b.len() as int] == 0u8);
        assert(a.contains(0u8));
    }
    assert(a.len() == b.len());
    assert((a + seq![0u8] + k).len() == a.len() + 1 + k.len());
    assert((b + seq![0u8] + q).len() == b.len() + 1 + q.len());
    assert(a =~= b) by {
        assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
            assert((a + seq![0u8] + k)[i] == a[i]);
            assert((b + seq![0u8] + q)[i] == b[i]);
        }
    }
    assert(k =~= q) by {
        assert forall|i: int| 0 <= i < k.len() implies k[i] == q[i] by {
            assert((a + seq![0u8] + k)[a.len() + 1 + i] == k[i]);
            assert((b + seq![0u8] + q)[b.len() + 1 + i] == q[i]);
        }
    }
}

}
