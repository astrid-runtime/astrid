//! Canonical UUID bytes for durable token markers.
use vstd::prelude::*;

verus! {

spec fn offset(i: int) -> int {
    2 * i + (if i < 4 { 0int } else if i < 6 { 1 } else if i < 8 { 2 }
        else if i < 10 { 3 } else { 4 })
}

#[allow(clippy::arithmetic_side_effects, reason = "the verifier bounds each UUID digit offset")]
fn position(i: usize) -> (out: usize)
    requires i < 16,
    ensures out == offset(i as int), out < 35,
{
    2 * i + if i < 4 { 0 } else if i < 6 { 1 } else if i < 8 { 2 }
        else if i < 10 { 3 } else { 4 }
}

spec fn code(n: int) -> int {
    if n < 10 { b'0' as int + n } else { b'a' as int + (n - 10) }
}

#[allow(clippy::arithmetic_side_effects, reason = "both hexadecimal branches fit one byte")]
fn digit(n: u8) -> (out: u8)
    requires n < 16,
    ensures out == code(n as int),
{
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

#[allow(clippy::arithmetic_side_effects, reason = "the ASCII ranges bound both subtractions")]
fn value(c: u8) -> (out: Option<u8>)
    ensures forall|n: int| 0 <= n < 16 && c == #[trigger] code(n) ==> out == Some(n as u8),
        out matches Some(n) ==> n < 16 && code(n as int) == c,
{
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

spec fn pair(id: Seq<u8>, text: Seq<u8>, i: int) -> bool {
    text[offset(i)] == code(id[i] as int / 16) && text[offset(i) + 1] == code(id[i] as int % 16)
}

pub(super) closed spec fn spells(id: Seq<u8>, text: Seq<u8>) -> bool {
    id.len() == 16 && text.len() == 36 && text[8] == 45 && text[13] == 45
        && text[18] == 45 && text[23] == 45 &&
        forall|i: int| 0 <= i < 16 ==> #[trigger] pair(id,text,i)
}

#[allow(clippy::arithmetic_side_effects, reason = "the verifier bounds every fixed-size array index")]
pub(super) fn encode(id: &[u8; 16]) -> (text: [u8; 36])
    ensures spells(id@, text@),
{
    let mut text = [b'-'; 36];
    let mut i = 0usize;
    while i < 16
        invariant i <= 16, text[8] == 45, text[13] == 45, text[18] == 45, text[23] == 45,
            forall|j: int| 0 <= j < i ==> #[trigger] pair(id@, text@, j),
        decreases 16 - i,
    {
        let p = position(i);
        let ghost before = text@;
        text[p] = digit(id[i] / 16);
        text[p + 1] = digit(id[i] % 16);
        assert forall|j: int| 0 <= j <= i implies #[trigger] pair(id@, text@, j) by {
            if j < i { assert(pair(id@, before, j)); assert(offset(j) + 1 < offset(i as int)); }
        }
        i += 1;
    }
    text
}

#[allow(clippy::arithmetic_side_effects, reason = "the verifier bounds UUID indices and digit assembly")]
pub(super) fn decode(text: &[u8]) -> (out: Option<[u8; 16]>)
    ensures forall|id: [u8; 16]| #[trigger] spells(id@, text@) ==> out == Some(id),
        out matches Some(id) ==> spells(id@, text@),
{
    if text.len() != 36 || text[8] != b'-' || text[13] != b'-' || text[18] != b'-' || text[23] != b'-' {
        return None;
    }
    let mut bytes = [0u8; 16];
    let mut i = 0usize;
    while i < 16
        invariant i <= 16, text.len() == 36, text[8] == 45, text[13] == 45, text[18] == 45, text[23] == 45,
            forall|j: int| 0 <= j < i ==> #[trigger] pair(bytes@, text@, j),
            forall|id: [u8; 16], j: int| spells(id@, text@) && 0 <= j < i ==> bytes[j] == #[trigger] id[j],
        decreases 16 - i,
    {
        let p = position(i);
        proof {
            assert forall|id: [u8; 16]| #[trigger] spells(id@, text@) implies pair(id@, text@, i as int) by {};
        }
        let hi = value(text[p])?;
        let lo = value(text[p + 1])?;
        let ghost before = bytes@;
        bytes[i] = hi * 16 + lo;
        assert forall|j: int| 0 <= j <= i implies #[trigger] pair(bytes@, text@, j) by {
            if j < i { assert(pair(before, text@, j)); }
        }
        i += 1;
    }
    proof {
        assert forall|id: [u8; 16]| #[trigger] spells(id@, text@) implies bytes == id by {
            assert(bytes@ =~= id@);
        }
    }
    Some(bytes)
}
}
