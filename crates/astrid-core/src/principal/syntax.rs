//! Byte grammar used by the validated principal ID constructor.

use vstd::prelude::*;

verus! {

pub(super) enum Syntax {
    Valid,
    Empty,
    TooLong,
    InvalidAt(usize),
}

pub(super) open spec fn allowed(b: u8) -> bool {
    (b'A' <= b && b <= b'Z') || (b'a' <= b && b <= b'z') ||
    (b'0' <= b && b <= b'9') || b == b'-' || b == b'_'
}

pub(super) fn classify(bytes: &[u8]) -> (result: Syntax)
    ensures match result {
        Syntax::Empty => bytes.len() == 0,
        Syntax::TooLong => bytes.len() > 64,
        Syntax::Valid => 1 <= bytes.len() <= 64 && forall|i: int| 0 <= i < bytes.len() ==> allowed(#[trigger] bytes@[i]),
        Syntax::InvalidAt(index) => 1 <= bytes.len() <= 64 && index < bytes.len()
            && !allowed(bytes@[index as int]) && forall|i: int| 0 <= i < index ==> allowed(#[trigger] bytes@[i]),
    },
{
    if bytes.is_empty() { return Syntax::Empty; }
    if bytes.len() > 64 { return Syntax::TooLong; }
    let mut i = 0;
    while i < bytes.len()
        invariant 1 <= bytes.len() <= 64, i <= bytes.len(),
            forall|j: int| 0 <= j < i ==> allowed(#[trigger] bytes@[j]),
        decreases bytes.len() - i,
    {
        let b = bytes[i];
        if !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') {
            return Syntax::InvalidAt(i);
        }
        i = i.saturating_add(1);
    }
    Syntax::Valid
}

}
