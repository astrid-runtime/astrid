//! Counters over the stored logical records preceding an ASTWAL2 Commit.
use super::{
    commit_wire::Counts,
    record_wire::{HEADER_LEN, WalRecordKind},
};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
pub(super) enum Entry { Object, Root }

pub(super) enum Overflow { Objects, Roots, Bytes, Ordinals }

pub(super) fn length(body: &[u8]) -> (bytes: Option<u64>)
    ensures bytes.is_some() == (HEADER_LEN as int + body.len() <= u64::MAX),
        bytes matches Some(n) ==> n as int == HEADER_LEN as int + body.len(),
{
    (HEADER_LEN as u64).checked_add(body.len() as u64)
}

pub(super) fn begin(sequence: u64, body: &[u8]) -> (counts: Option<Counts>)
    ensures counts.is_some() == (HEADER_LEN as int + body.len() <= u64::MAX),
        counts matches Some(c) ==> c.sequence == sequence && c.logical == 1
            && c.objects == 0 && c.roots == 0 && c.bytes as int == HEADER_LEN as int + body.len(),
{
    Some(Counts { sequence, logical: 1, objects: 0, roots: 0, bytes: length(body)? })
}

pub(super) fn append(before: Counts, entry: Entry, body: &[u8]) -> (result: Result<Counts, Overflow>)
    ensures
        result.is_ok() == (before.logical < u64::MAX &&
            before.bytes as int + HEADER_LEN as int + body.len() <= u64::MAX &&
            (match entry { Entry::Object => before.objects < u64::MAX, Entry::Root => before.roots < u64::MAX })),
        result matches Ok(c) ==> c.sequence == before.sequence &&
            c.logical as int == before.logical as int + 1 &&
            c.objects as int == before.objects as int + (if entry is Object {1int} else {0int}) &&
            c.roots as int == before.roots as int + (if entry is Root {1int} else {0int}) &&
            c.bytes as int == before.bytes as int + HEADER_LEN as int + body.len(),
{
    let mut next = before;
    match entry {
        Entry::Object => next.objects = before.objects.checked_add(1).ok_or(Overflow::Objects)?,
        Entry::Root => next.roots = before.roots.checked_add(1).ok_or(Overflow::Roots)?,
    }
    let size = length(body).ok_or(Overflow::Bytes)?;
    next.bytes = before.bytes.checked_add(size).ok_or(Overflow::Bytes)?;
    next.logical = before.logical.checked_add(1).ok_or(Overflow::Ordinals)?;
    Ok(next)
}

pub(super) open spec fn digest_header(kind: WalRecordKind, flags: u8, sequence: u64,
    ordinal: u64, size: u64) -> Seq<u8>
{
    let tag: u8 = match kind {
        WalRecordKind::Begin => 1, WalRecordKind::Object => 2,
        WalRecordKind::Root => 3, WalRecordKind::Commit => 4,
    };
    (if flags == 0 { seq![tag] } else { seq![255u8,tag,flags] })
        + vstd::bytes::spec_u64_to_le_bytes(sequence)
        + vstd::bytes::spec_u64_to_le_bytes(ordinal)
        + vstd::bytes::spec_u64_to_le_bytes(size)
}

/// Present the canonical header and the original stored payload as two slices.
/// This keeps the payload borrowed, including compressed object bodies.
pub(super) fn digest_record<T,F>(kind: WalRecordKind, flags: u8, sequence: u64, ordinal: u64,
    body: &[u8], update: F) -> (result:T) where F: FnOnce(&[u8], &[u8]) -> T,
    requires forall|h:&[u8]| #[trigger] update.requires((h,body)),
    ensures exists|h:&[u8]| h@ == digest_header(kind,flags,sequence,ordinal,body.len() as u64)
        && #[trigger] update.ensures((h,body),result),
{
    let mut header = [0u8;27];
    let tag = kind.tag();
    let start = if flags == 0 { header[2] = tag; 2usize } else {
        header[0] = 255; header[1] = tag; header[2] = flags; 0usize
    };
    header[3..11].copy_from_slice(&super::commit_wire::little_endian(sequence));
    header[11..19].copy_from_slice(&super::commit_wire::little_endian(ordinal));
    header[19..].copy_from_slice(&super::commit_wire::little_endian(body.len() as u64));
    let prefix = &header[start..];
    assert(prefix@ =~= digest_header(kind,flags,sequence,ordinal,body.len() as u64));
    let result = update(prefix,body);
    assert(update.ensures((prefix,body),result));
    result
}

}

impl Overflow {
    pub(super) fn field(self, logical: &'static str) -> &'static str {
        match self {
            Self::Objects => "objects",
            Self::Roots => "roots",
            Self::Bytes => "logical bytes",
            Self::Ordinals => logical,
        }
    }
}
