//! Bytes remaining in one length-prefixed socket frame after short writes.

use vstd::prelude::*;

verus! {

/// Construct the wire header for this body, rejecting unrepresentable lengths.
#[expect(clippy::cast_possible_truncation, reason = "Verus checks exact representability of the four wire bytes")]
pub(super) fn body_prefix(body: &[u8]) -> (prefix: Option<[u8; 4]>)
    ensures
        prefix.is_some() == (body.len() <= u32::MAX),
        prefix matches Some(bytes) ==> (
            bytes[0] as int * 16777216 + bytes[1] as int * 65536
            + bytes[2] as int * 256 + bytes[3] as int == body.len()
        ),
{
    if body.len() > u32::MAX as usize { return None; }
    let n = body.len() as u32;
    let upper = n / 256;
    let high = upper / 256;
    Some([(high / 256) as u8, (high % 256) as u8, (upper % 256) as u8, (n % 256) as u8])
}

pub(super) struct FrameSegments<'a> {
    prefix: &'a [u8],
    body: &'a [u8],
}

impl<'a> FrameSegments<'a> {
    pub(super) closed spec fn remaining(&self) -> Seq<u8> {
        self.prefix@ + self.body@
    }

    pub(super) fn new(prefix: &'a [u8; 4], body: &'a [u8]) -> (frame: Self)
        ensures frame.remaining() == prefix@ + body@,
    {
        Self { prefix: prefix.as_slice(), body }
    }

    pub(super) closed spec fn offered(&self) -> nat {
        if self.prefix.len() == 0 { self.body@.len() } else { self.prefix@.len() }
    }

    pub(super) fn next(&self) -> (bytes: &'a [u8])
        ensures
            bytes@ == self.remaining().take(bytes.len() as int),
            bytes.len() == self.offered(),
            bytes.len() <= self.remaining().len(),
            (bytes.len() == 0) == (self.remaining().len() == 0),
    {
        if self.prefix.is_empty() { self.body } else { self.prefix }
    }

    /// Advance only by a positive count reported for the slice actually offered.
    pub(super) fn accept(&mut self, count: usize) -> (ok: bool)
        ensures
            ok == (0 < count <= old(self).offered()),
            final(self).remaining() == if ok { old(self).remaining().skip(count as int) }
                else { old(self).remaining() },
    {
        let segment = if self.prefix.is_empty() { &mut self.body } else { &mut self.prefix };
        if count == 0 || count > segment.len() {
            return false;
        }
        let (_, suffix) = segment.split_at(count);
        *segment = suffix;
        true
    }
}

}
