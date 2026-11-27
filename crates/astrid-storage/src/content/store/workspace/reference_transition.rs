//! Workspace branch and promotion receipt references in an owner root.
#[cfg(verus_keep_ghost)]
use super::ReferenceKind;
use super::{ObjectId, ObjectReference, ReferenceLabel};
use vstd::prelude::*;

verus! {
pub(super) const BRANCH_REF_PREFIX_BYTES: &[u8;10] = b"workspace/";
pub(super) const BRANCH_RECEIPT_PREFIX_BYTES: &[u8;19] = b"workspace-promoted/";

pub(super) open spec fn nibble(byte: u8) -> Option<u8> {
    if 48 <= byte <= 57 { Some((byte - 48) as u8) }
    else if 65 <= byte <= 70 { Some((byte - 55) as u8) }
    else if 97 <= byte <= 102 { Some((byte - 87) as u8) }
    else { None }
}

fn digit(byte: u8) -> (out: Option<u8>)
    ensures out == nibble(byte), out matches Some(n) ==> n < 16,
{
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) open spec fn decodes(text: Seq<u8>, id: [u8;16]) -> bool {
    text.len() == 32 && forall|i:int| 0 <= i < 16 ==>
        nibble(text[2*i]) == Some((#[trigger] id@[i] / 16) as u8)
        && nibble(text[2*i+1]) == Some((id@[i] % 16) as u8)
}

fn decode(text: &[u8]) -> (out: Option<[u8;16]>)
    ensures forall|id:[u8;16]| (out == Some(id)) == #[trigger] decodes(text@,id),
{
    if text.len() != 32 { return None; }
    let mut id = [0u8;16];
    let mut i = 0usize;
    while i < id.len()
        invariant i <= 16, text.len() == 32,
            forall|j:int| 0 <= j < i ==> nibble(text@[2*j]) == Some((#[trigger] id@[j] / 16) as u8)
                && nibble(text@[2*j+1]) == Some((id@[j] % 16) as u8),
        decreases 16-i,
    {
        let Some(high) = digit(text[2*i]) else {
            assert forall|other:[u8;16]| !decodes(text@,other) by { let b = other@[i as int]; }
            return None;
        };
        let Some(low) = digit(text[2*i+1]) else {
            assert forall|other:[u8;16]| !decodes(text@,other) by { let b = other@[i as int]; }
            return None;
        };
        id[i] = high * 16 + low;
        i += 1;
    }
    assert(decodes(text@,id));
    assert forall|other:[u8;16]| decodes(text@,other) implies other == id by {
        assert(other@ =~= id@) by {
            assert forall|j:int| 0 <= j < 16 implies other@[j] == id@[j] by {
                assert(nibble(text@[2*j]) == Some((other@[j]/16) as u8));
                assert(nibble(text@[2*j]) == Some((id@[j]/16) as u8));
            }
        }
    }
    Some(id)
}

pub(super) open spec fn branch_label(label: Seq<u8>, id: [u8;16]) -> bool {
    let prefix = BRANCH_REF_PREFIX_BYTES@;
    decodes(if label.len() >= prefix.len() && label.take(prefix.len() as int) == prefix { label.skip(prefix.len() as int) } else { label },id)
}

pub(super) open spec fn receipt_label(label: Seq<u8>, id: [u8;16]) -> bool {
    let prefix = BRANCH_RECEIPT_PREFIX_BYTES@;
    label.len() >= prefix.len() && label.take(prefix.len() as int) == prefix && branch_label(label.skip(prefix.len() as int),id)
}

fn strip<'a>(label: &'a [u8], prefix: &[u8]) -> (out: Option<&'a [u8]>)
    ensures if label@.len() >= prefix@.len() && label@.take(prefix@.len() as int) == prefix@ {
        out matches Some(rest) && rest@ == label@.skip(prefix@.len() as int)
    } else { out.is_none() },
{
    if label.len() < prefix.len() { return None; }
    let (start, rest) = label.split_at(prefix.len());
    if start != prefix { return None; }
    assert(start@ =~= prefix@);
    Some(rest)
}

pub(super) fn branch(label: &[u8]) -> (out: Option<[u8;16]>)
    ensures forall|id:[u8;16]| (out == Some(id)) == #[trigger] branch_label(label@,id),
{
    let prefix = BRANCH_REF_PREFIX_BYTES;
    match strip(label,prefix) { Some(rest) => decode(rest), None => decode(label) }
}

pub(super) fn receipt(label: &[u8]) -> (out: Option<[u8;16]>)
    ensures forall|id:[u8;16]| (out == Some(id)) == #[trigger] receipt_label(label@,id),
{
    let prefix = BRANCH_RECEIPT_PREFIX_BYTES;
    let rest = strip(label,prefix)?;
    branch(rest)
}

pub(super) open spec fn lower(n: u8) -> u8 { if n < 10 { (48+n) as u8 } else { (87+n) as u8 } }

fn encode_digit(n: u8) -> (byte: u8)
    requires n < 16,
    ensures byte == lower(n), nibble(byte) == Some(n),
{
    if n < 10 { b'0' + n } else { b'a' + (n-10) }
}

pub(super) fn encode_receipt(id: [u8;16]) -> (bytes: Vec<u8>)
    ensures receipt_label(bytes@,id),
        bytes@.take(29) == BRANCH_RECEIPT_PREFIX_BYTES@ + BRANCH_REF_PREFIX_BYTES@,
        bytes@.len() == 61,
        forall|j:int| 0 <= j < 16 ==> bytes@[29+2*j] == lower((#[trigger] id@[j]/16) as u8)
            && bytes@[30+2*j] == lower((id@[j]%16) as u8),
{
    let mut bytes = Vec::with_capacity(BRANCH_RECEIPT_PREFIX_BYTES.len() + BRANCH_REF_PREFIX_BYTES.len() + 2 * id.len());
    bytes.extend_from_slice(BRANCH_RECEIPT_PREFIX_BYTES);
    bytes.extend_from_slice(BRANCH_REF_PREFIX_BYTES);
    let mut i = 0usize;
    while i < id.len()
        invariant i <= 16, bytes@.len() == 29 + 2*i,
            bytes@.take(29) == BRANCH_RECEIPT_PREFIX_BYTES@ + BRANCH_REF_PREFIX_BYTES@,
            forall|j:int| 0 <= j < i ==> bytes@[29+2*j] == lower((#[trigger] id@[j]/16) as u8)
                && bytes@[30+2*j] == lower((id@[j]%16) as u8)
                && nibble(bytes@[29+2*j]) == Some((id@[j]/16) as u8)
                && nibble(bytes@[30+2*j]) == Some((id@[j]%16) as u8),
        decreases 16-i,
    {
        let b = id[i];
        bytes.push(encode_digit(b/16));
        bytes.push(encode_digit(b%16));
        i += 1;
    }
    assert(bytes@.take(19) =~= BRANCH_RECEIPT_PREFIX_BYTES@);
    let ghost body = bytes@.skip(19);
    assert(body.take(10) =~= BRANCH_REF_PREFIX_BYTES@) by {
        assert forall|j:int| 0 <= j < 10 implies body.take(10)[j] == BRANCH_REF_PREFIX_BYTES@[j] by {
            assert(bytes@.take(29)[19+j] == (BRANCH_RECEIPT_PREFIX_BYTES@ + BRANCH_REF_PREFIX_BYTES@)[19+j]);
        }
    }
    assert forall|j:int| 0 <= j < 16 implies
        nibble(body.skip(10)[2*j]) == Some((#[trigger] id@[j]/16) as u8)
            && nibble(body.skip(10)[2*j+1]) == Some((id@[j]%16) as u8) by {
        assert(body.skip(10)[2*j] == bytes@[29+2*j]);
        assert(body.skip(10)[2*j+1] == bytes@[30+2*j]);
    }
    bytes
}

pub(super) open spec fn keep(reference:ObjectReference, id:[u8;16]) -> bool {
    !branch_label(reference.fields().0,id) && !receipt_label(reference.fields().0,id)
}

pub(super) open spec fn promotion(reference:ObjectReference, id:[u8;16], target:ObjectId) -> bool {
    &&& receipt_label(reference.fields().0,id)
    &&& reference.fields().1 == target
    &&& reference.fields().2 == ReferenceKind::Owns
}

/// Stable in-place removal, followed by the promotion receipt when present.
pub(super) fn rewrite(references: &mut Vec<ObjectReference>, id: [u8;16], receipt_id: Option<ObjectId>)
    ensures ({
        let survivors = old(references)@.filter(|r:ObjectReference| keep(r,id));
        match receipt_id {
            Some(target) => exists|r:ObjectReference| promotion(r,id,target) && final(references)@ == #[trigger] survivors.push(r),
            None => final(references)@ == survivors,
        }
    }),
{
    let ghost before = references@;
    let mut read = 0usize;
    let mut write = 0usize;
    while read < references.len()
        invariant write <= read <= references.len(), references@.len() == before.len(),
            references@.take(write as int) == before.take(read as int).filter(|r:ObjectReference| keep(r,id)),
            forall|j:int| read <= j < before.len() ==> #[trigger] references@[j] == before[j],
        decreases references.len()-read,
    {
        let label = references[read].label_bytes();
        let retain = branch(label) != Some(id) && receipt(label) != Some(id);
        assert(references@[read as int] == before[read as int]);
        assert(retain == keep(before[read as int],id));
        let ghost prefix = before.take(read as int+1);
        assert(prefix.drop_last() =~= before.take(read as int));
        assert(prefix.last() == before[read as int]);
        let ghost kept = references@.take(write as int);
        let ghost survivors = prefix.filter(|r:ObjectReference| keep(r,id));
        if retain {
            assert(survivors == kept.push(before[read as int])) by { reveal(Seq::filter); }
            if write != read { references.as_mut_slice().swap(write,read); }
            assert(references@[write as int] == before[read as int]);
            assert(references@.take(write as int+1) =~= kept.push(before[read as int]));
            write += 1;
        } else { assert(survivors == kept) by { reveal(Seq::filter); } }
        read += 1;
        assert(references@.take(write as int) =~= prefix.filter(|r:ObjectReference| keep(r,id)));
    }
    assert(before.take(read as int) =~= before);
    references.truncate(write);
    if let Some(target) = receipt_id {
        let record = ObjectReference::owns(ReferenceLabel::new(encode_receipt(id)),target);
        references.push(record);
        assert(promotion(record,id,target));
    }
}
}
