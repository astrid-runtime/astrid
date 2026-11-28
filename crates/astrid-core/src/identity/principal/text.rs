//! Canonical text for a 32-byte durable principal UID.

use vstd::prelude::*;

verus! {

spec fn hex_digit(n: int) -> int {
    if n < 10 { b'0' as int + n } else { b'a' as int + n - 10 }
}

spec fn lower_hex(c: u8) -> bool {
    b'0' <= c <= b'9' || b'a' <= c <= b'f'
}

pub(super) closed spec fn canonical(text: Seq<u8>) -> bool {
    text.len() == 64 && forall|i: int| 0 <= i < 64 ==> lower_hex(#[trigger] text[i])
}

spec fn same_byte(uid: Seq<u8>, text: Seq<u8>, i: int) -> bool {
    text[2 * i] == hex_digit(uid[i] as int / 16)
        && text[2 * i + 1] == hex_digit(uid[i] as int % 16)
}

pub(super) closed spec fn spells(uid: Seq<u8>, text: Seq<u8>) -> bool {
    uid.len() == 32 && text.len() == 64 &&
    forall|i: int| 0 <= i < 32 ==> #[trigger] same_byte(uid, text, i)
}

/// A canonical text used for a directory, audit field or wire identity cannot name two UIDs.
pub(super) proof fn unique_uid(a: Seq<u8>, b: Seq<u8>, text: Seq<u8>)
    requires spells(a, text), spells(b, text),
    ensures a == b,
{
    assert forall|i: int| 0 <= i < 32 implies a[i] == b[i] by {
        assert(same_byte(a, text, i));
        assert(same_byte(b, text, i));
    }
    assert(a =~= b);
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus checks both digit ranges")]
fn digit(n: u8) -> (c: u8)
    requires n < 16,
    ensures c == hex_digit(n as int), lower_hex(c),
{
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus checks all offsets in the fixed-size output")]
pub(super) fn encode(uid: &[u8; 32]) -> (text: [u8; 64])
    ensures spells(uid@, text@), canonical(text@),
{
    let mut text = [0u8; 64];
    let mut i: usize = 0;
    while i < 32
        invariant i <= 32,
            forall|k: int| 0 <= k < 2 * i ==> lower_hex(#[trigger] text[k]),
            forall|j: int| 0 <= j < i ==> #[trigger] same_byte(uid@, text@, j),
        decreases 32 - i,
    {
        let ghost old_text = text@;
        text[2 * i] = digit(uid[i] / 16);
        text[2 * i + 1] = digit(uid[i] % 16);
        assert forall|j: int| 0 <= j <= i implies #[trigger] same_byte(uid@, text@, j) by {
            if j < i { assert(same_byte(uid@, old_text, j)); }
        }
        i += 1;
    }
    text
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the digit subtractions and addition fit")]
fn nibble(c: u8) -> (n: Option<u8>)
    ensures n.is_some() == lower_hex(c),
        match n { Some(v) => v < 16 && hex_digit(v as int) == c, None => true },
{
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus checks the bounded byte offsets and nibble assembly")]
pub(super) fn decode(text: &[u8]) -> (uid: Option<[u8; 32]>)
    ensures uid.is_some() == canonical(text@),
        match uid { Some(bytes) => spells(bytes@, text@), None => true },
{
    if text.len() != 64 { return None; }
    let mut bytes = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant i <= 32, text.len() == 64,
            forall|k: int| 0 <= k < 2 * i ==> lower_hex(#[trigger] text[k]),
            forall|j: int| 0 <= j < i ==> #[trigger] same_byte(bytes@, text@, j),
        decreases 32 - i,
    {
        let high = nibble(text[2 * i])?;
        let low = nibble(text[2 * i + 1])?;
        let ghost old_bytes = bytes@;
        bytes[i] = high * 16 + low;
        assert forall|j: int| 0 <= j <= i implies #[trigger] same_byte(bytes@, text@, j) by {
            if j < i { assert(same_byte(old_bytes, text@, j)); }
        }
        i += 1;
    }
    Some(bytes)
}
}
