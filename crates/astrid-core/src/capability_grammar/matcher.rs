//! Allocation-free matching for colon-delimited static capabilities.

use vstd::prelude::*;

verus! {

spec fn is_end(bytes: Seq<u8>, start: int, end: int) -> bool {
    0 <= start <= end <= bytes.len()
    && (end == bytes.len() || bytes[end] == b':')
    && forall|i: int| start <= i < end ==> bytes[i] != b':'
}

spec fn end_of(bytes: Seq<u8>, start: int) -> int {
    choose|end: int| is_end(bytes, start, end)
}

proof fn end_is_unique(bytes: Seq<u8>, start: int, end: int)
    requires is_end(bytes, start, end),
    ensures end == end_of(bytes, start),
{
    let selected = end_of(bytes, start);
    assert(is_end(bytes, start, selected));
    if end < selected {
        assert(bytes[end] == b':');
        assert(bytes[end] != b':');
    } else if selected < end {
        assert(bytes[selected] == b':');
        assert(bytes[selected] != b':');
    }
}

spec fn star(bytes: Seq<u8>, start: int, end: int) -> bool {
    end == start + 1 && bytes[start] == b'*'
}

spec fn equal_segment(p: Seq<u8>, c: Seq<u8>, i: int, j: int, len: int) -> bool {
    forall|k: int| 0 <= k < len ==> #[trigger] p[i + k] == #[trigger] c[j + k]
}

pub(super) closed spec fn matches_from(p: Seq<u8>, c: Seq<u8>, i: int, j: int) -> bool
    decreases p.len() - i,
{
    let pe = end_of(p, i);
    let ce = end_of(c, j);
    if !(0 <= i <= pe <= p.len() && 0 <= j <= c.len()) {
        false
    } else if star(p, i, pe) && pe == p.len() {
        true
    } else if !(j <= ce <= c.len()) {
        false
    } else if !(star(p, i, pe) || (pe - i == ce - j && equal_segment(p, c, i, j, pe - i))) {
        false
    } else if pe == p.len() || ce == c.len() {
        pe == p.len() && ce == c.len()
    } else {
        matches_from(p, c, pe + 1, ce + 1)
    }
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the index and arithmetic bounds")]
fn segment_end(bytes: &[u8], start: usize) -> (end: usize)
    requires start <= bytes.len(),
    ensures is_end(bytes@, start as int, end as int), end as int == end_of(bytes@, start as int),
{
    let mut end = start;
    while end < bytes.len() && bytes[end] != b':'
        invariant
            start <= end <= bytes.len(),
            forall|pattern_start: int| start <= pattern_start < end ==> bytes@[pattern_start] != b':',
        decreases bytes.len() - end,
    {
        end += 1;
    }
    proof { end_is_unique(bytes@, start as int, end as int); }
    end
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the index and arithmetic bounds")]
fn literal_eq(pattern: &[u8], capability: &[u8], pattern_start: usize, capability_start: usize, len: usize) -> (same: bool)
    requires pattern_start as int + len as int <= pattern.len(), capability_start as int + len as int <= capability.len(),
    ensures same == equal_segment(pattern@, capability@, pattern_start as int, capability_start as int, len as int),
{
    let mut offset = 0;
    while offset < len
        invariant
            offset <= len,
            pattern_start as int + len as int <= pattern.len(),
            capability_start as int + len as int <= capability.len(),
            equal_segment(pattern@, capability@, pattern_start as int, capability_start as int, offset as int),
        decreases len - offset,
    {
        if pattern[pattern_start + offset] != capability[capability_start + offset] {
            assert(!equal_segment(pattern@, capability@, pattern_start as int, capability_start as int, len as int));
            return false;
        }
        offset += 1;
    }
    true
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the index and arithmetic bounds")]
pub(super) fn matches(pattern: &[u8], capability: &[u8]) -> (result: bool)
    ensures result == matches_from(pattern@, capability@, 0, 0),
{
    let mut pattern_start = 0;
    let mut capability_start = 0;
    loop
        invariant
            pattern_start <= pattern.len(),
            capability_start <= capability.len(),
            matches_from(pattern@, capability@, pattern_start as int, capability_start as int) == matches_from(pattern@, capability@, 0, 0),
        decreases pattern.len() - pattern_start,
    {
        let pattern_end = segment_end(pattern, pattern_start);
        let wildcard = pattern_end - pattern_start == 1 && pattern[pattern_start] == b'*';
        if wildcard && pattern_end == pattern.len() {
            return true;
        }
        let capability_end = segment_end(capability, capability_start);
        if !wildcard && (pattern_end - pattern_start != capability_end - capability_start || !literal_eq(pattern, capability, pattern_start, capability_start, pattern_end - pattern_start)) {
            return false;
        }
        if pattern_end == pattern.len() || capability_end == capability.len() {
            return pattern_end == pattern.len() && capability_end == capability.len();
        }
        pattern_start = pattern_end + 1;
        capability_start = capability_end + 1;
    }
}

}
