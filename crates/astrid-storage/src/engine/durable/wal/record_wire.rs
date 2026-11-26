//! Logical record header shared by the WAL writer and scanner.
use vstd::prelude::*;

verus! {

pub(super) const HEADER_LEN: usize = 20;

pub(super) struct Header {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) reserved: [u8;2],
    pub(super) sequence: [u8;8],
    pub(super) ordinal: [u8;8],
}

impl Header {
    pub(super) open spec fn bytes(&self) -> Seq<u8> {
        seq![self.kind,self.flags] + self.reserved@ + self.sequence@ + self.ordinal@
    }

    pub(super) fn append(&self, encoded: &mut Vec<u8>, body: &[u8])
        ensures final(encoded)@ == old(encoded)@ + self.bytes() + body@,
    {
        encoded.extend_from_slice(&[self.kind, self.flags, self.reserved[0], self.reserved[1]]);
        encoded.extend_from_slice(&self.sequence);
        encoded.extend_from_slice(&self.ordinal);
        encoded.extend_from_slice(body);
        assert(encoded@ =~= old(encoded)@ + self.bytes() + body@);
    }
}

pub(super) fn split(payload: &[u8]) -> (fields: Option<(Header,&[u8])>)
    ensures fields.is_some() == (payload.len() >= HEADER_LEN),
        fields matches Some((h,body)) ==> h.bytes() + body@ == payload@
            && h.kind == payload@[0] && h.flags == payload@[1]
            && h.reserved@ == payload@.subrange(2,4)
            && h.sequence@ == payload@.subrange(4,12)
            && h.ordinal@ == payload@.subrange(12,20)
            && body@ == payload@.skip(HEADER_LEN as int),
{
    if payload.len() < HEADER_LEN { return None; }
    let mut sequence = [0;8];
    sequence.copy_from_slice(&payload[4..12]);
    let mut ordinal = [0;8];
    ordinal.copy_from_slice(&payload[12..20]);
    let header = Header {kind: payload[0], flags: payload[1], reserved: [payload[2],payload[3]], sequence, ordinal};
    let body = &payload[HEADER_LEN..];
    assert(header.reserved@ =~= payload@.subrange(2,4));
    assert(header.bytes() + body@ =~= payload@);
    Some((header,body))
}

pub(super) enum PositionError { Sequence, Ordinal }

/// Deliver the same body to dispatch only at the current transaction position.
pub(super) fn body_at_position(body: &[u8], sequence: u64, ordinal: u64,
    expected_sequence: u64, expected_ordinal: u64) -> (result: Result<&[u8],PositionError>)
    ensures
        result.is_ok() == (sequence == expected_sequence && ordinal == expected_ordinal),
        result matches Ok(accepted) ==> accepted == body,
        (result matches Err(PositionError::Sequence)) == (sequence != expected_sequence),
        (result matches Err(PositionError::Ordinal)) == (sequence == expected_sequence && ordinal != expected_ordinal),
{
    if sequence != expected_sequence { return Err(PositionError::Sequence); }
    if ordinal != expected_ordinal { return Err(PositionError::Ordinal); }
    Ok(body)
}

}
