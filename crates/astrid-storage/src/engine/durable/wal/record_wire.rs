//! Logical record header shared by the WAL writer and scanner.
use vstd::prelude::*;

verus! {

/// A kind byte in the ASTWAL2 logical record grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WalRecordKind {
    /// Starts one transaction.
    Begin,
    /// Carries one canonical immutable object frame.
    Object,
    /// Carries one canonical principal-root transition.
    Root,
    /// Commits one transaction after all prior records.
    Commit,
}

impl WalRecordKind {
    /// Return the stable wire tag.
    pub(super) fn tag(self) -> (tag: u8)
        ensures tag == match self { Self::Begin => 1u8, Self::Object => 2, Self::Root => 3, Self::Commit => 4 },
    {
        match self {
            Self::Begin => 1,
            Self::Object => 2,
            Self::Root => 3,
            Self::Commit => 4,
        }
    }

    /// Decode a stable wire tag.
    pub(super) fn from_tag(tag: u8) -> (kind: Option<Self>)
        ensures kind == match tag { 1 => Some(Self::Begin), 2 => Some(Self::Object), 3 => Some(Self::Root), 4 => Some(Self::Commit), _ => None },
    {
        match tag {
            1 => Some(Self::Begin),
            2 => Some(Self::Object),
            3 => Some(Self::Root),
            4 => Some(Self::Commit),
            _ => None,
        }
    }
}

pub(super) const HEADER_LEN: usize = 20;

pub(super) struct Header {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) reserved: [u8;2],
    pub(super) sequence: [u8;8],
    pub(super) ordinal: [u8;8],
}

pub(super) enum HeaderError { UnknownKind, InvalidFeatures }

impl Header {
    /// Validate the kind, flags and reserved bytes before accepting a body.
    pub(super) fn classify(&self) -> (out:Result<WalRecordKind,HeaderError>)
        ensures out.is_ok() == (1 <= self.kind <= 4 && self.reserved@[0] == 0 && self.reserved@[1] == 0 &&
                    (self.flags == 0 || (self.kind == 2 && self.flags == 1))),
            out matches Ok(kind) ==> self.kind == match kind {
                WalRecordKind::Begin=>1u8,WalRecordKind::Object=>2,WalRecordKind::Root=>3,WalRecordKind::Commit=>4,
            },
            (out matches Err(HeaderError::UnknownKind)) == !(1 <= self.kind <= 4),
    {
        let kind = WalRecordKind::from_tag(self.kind).ok_or(HeaderError::UnknownKind)?;
        if self.reserved != [0;2] || (self.flags != 0 && !(matches!(kind,WalRecordKind::Object) && self.flags == 1)) {
            return Err(HeaderError::InvalidFeatures);
        }
        Ok(kind)
    }


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
