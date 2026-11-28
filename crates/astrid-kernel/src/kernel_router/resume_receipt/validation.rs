//! Receipt identity, digest syntax and exact read-back acknowledgement.

use vstd::prelude::*;

verus! {

pub(super) open spec fn lower_hex(bytes: Seq<u8>) -> bool {
    bytes.len() == 64 && forall|i: int| 0 <= i < bytes.len() ==>
        (48 <= #[trigger] bytes[i] <= 57 || 97 <= bytes[i] <= 102)
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the index remains within the 64-byte digest")]
fn digest(bytes: &[u8]) -> (accepted: bool)
    ensures accepted == lower_hex(bytes@),
{
    if bytes.len() != 64 { return false; }
    let mut i = 0usize;
    while i < bytes.len()
        invariant bytes.len() == 64, i <= bytes.len(),
            forall|j: int| 0 <= j < i ==> (48 <= #[trigger] bytes@[j] <= 57 || 97 <= bytes@[j] <= 102),
        decreases bytes.len() - i,
    {
        let byte = bytes[i];
        if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
            assert(!lower_hex(bytes@));
            return false;
        }
        i += 1;
    }
    true
}

pub(super) fn valid(id: &str, key: &str, archive: &[u8], installed: &[u8], metadata: &[u8], authority: &[u8]) -> (ok: bool)
    ensures ok == (id@ == key@ && lower_hex(archive@) && lower_hex(installed@)
        && lower_hex(metadata@) && lower_hex(authority@)),
{
    id == key && digest(archive) && digest(installed) && digest(metadata) && digest(authority)
}

/// A successful compare-and-swap must be followed by an exact read-back.
pub(super) fn after_swap<T>(swapped: bool, target: T) -> (pending: Option<T>)
    ensures pending == if swapped { Some(target) } else { None },
{
    if swapped { Some(target) } else { None }
}

pub(super) fn confirmed(expected: &[u8], observed: Option<&[u8]>) -> (ok: bool)
    ensures ok == (match observed { Some(bytes) => bytes@ =~= expected@, None => false }),
{
    match observed {
        Some(bytes) => bytes == expected,
        None => false,
    }
}

}
