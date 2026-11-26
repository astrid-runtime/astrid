//! Recovery contracts for complete and incomplete scanner event prefixes.
use crate::commit_wire::{CheckedMarker,Counts,Marker};
use crate::wal_transaction::{self as tx, Batch,Event,Origin,Step};
use vstd::prelude::*;

verus! {

proof fn unique_marker(decoded: Marker, marker: Marker)
    requires decoded.wire() == marker.wire(),
    ensures decoded == marker,
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    assert(decoded.counts == marker.counts) by {
        assert(decoded.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(decoded.counts.sequence));
        assert(decoded.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(decoded.counts.logical));
        assert(decoded.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(decoded.counts.objects));
        assert(decoded.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(decoded.counts.roots));
        assert(decoded.wire().subrange(32,40) =~= vstd::bytes::spec_u64_to_le_bytes(decoded.counts.bytes));
        assert(marker.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(marker.counts.sequence));
        assert(marker.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(marker.counts.logical));
        assert(marker.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(marker.counts.objects));
        assert(marker.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(marker.counts.roots));
        assert(marker.wire().subrange(32,40) =~= vstd::bytes::spec_u64_to_le_bytes(marker.counts.bytes));
    }
    assert(decoded.wire().skip(40) =~= decoded.digest@);
    assert(marker.wire().skip(40) =~= marker.digest@);
    assert(decoded.digest@ =~= marker.digest@);
    assert(decoded.digest == marker.digest);
    assert(decoded == marker);
}

/// An arbitrary scanner input matches the observed transaction iff the fixed
/// body is its canonical encoding and the observed sequence is nonzero.
fn check_body(body: &[u8], observed: Counts, digest: [u8;32]) -> (accepted: Option<CheckedMarker>)
    ensures accepted.is_some() == (observed.sequence != 0 && body@ == (Marker {counts: observed, digest}).wire()),
        accepted matches Some(m) ==> m.marker() == (Marker {counts: observed, digest}),
{
    let ghost expected = Marker {counts: observed, digest};
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(expected.wire().len() == 72);
    let decoded = crate::commit_wire::decode(body)?;
    proof { if body@ == expected.wire() { unique_marker(decoded,expected); } }
    if decoded.counts.sequence == 0 { return None; }
    let finish = || -> (d:[u8;32]) ensures d == digest {digest};
    match decoded.confirm(&observed,finish) {
        Ok(checked) => Some(checked), Err(_) => None,
    }
}

fn writer_marker_is_readable(marker: Marker) requires marker.counts.sequence != 0 {
    let bytes = marker.encode();
    let accepted = check_body(&bytes,marker.counts,marker.digest);
    assert(accepted matches Some(m) && m.marker() == marker);
}

/// The concrete accumulator retains the order and identity of arbitrary
/// (including non-Copy) descriptors. The scanner emits objects before roots.
fn pending_descriptors<'a,O,R>(origin: Origin, objects: &'a [O], roots: &'a [R])
    -> (out: Option<Batch<&'a O,&'a R>>)
    ensures out matches Some(batch) && {
        let image = batch.contents();
        &&& image.origin == origin
        &&& image.objects.len() == objects.len()
        &&& image.roots.len() == roots.len()
        &&& forall|j:int| 0 <= j < objects.len() ==> *#[trigger] image.objects[j] == objects@[j]
        &&& forall|j:int| 0 <= j < roots.len() ==> *#[trigger] image.roots[j] == roots@[j]
    },
{
    let mut batch = match tx::advance(None,Event::<&O,&R>::Begin(origin)) {
        Ok(Step::Pending(b)) => b, _ => { assert(false); return None; },
    };
    let mut i = 0;
    while i < objects.len()
        invariant i <= objects.len(), batch.contents().origin == origin,
            batch.contents().objects.len() == i, batch.contents().roots.len() == 0,
            forall|j:int| 0 <= j < i ==> *#[trigger] batch.contents().objects[j] == objects@[j],
        decreases objects.len() - i,
    {
        batch = match tx::advance(Some(batch),Event::Object(&objects[i])) {
            Ok(Step::Pending(b)) => b, _ => { assert(false); return None; },
        };
        i += 1;
    }
    let ghost staged = batch.contents().objects;
    let mut k = 0;
    while k < roots.len()
        invariant k <= roots.len(), batch.contents().origin == origin,
            batch.contents().objects == staged, batch.contents().roots.len() == k,
            forall|j:int| 0 <= j < k ==> *#[trigger] batch.contents().roots[j] == roots@[j],
        decreases roots.len() - k,
    {
        batch = match tx::advance(Some(batch),Event::Root(&roots[k])) {
            Ok(Step::Pending(b)) => b, _ => { assert(false); return None; },
        };
        k += 1;
    }
    Some(batch)
}

/// A torn tail never yields a replayable transaction. A marker yields exactly
/// the gathered descriptors only for the same begin offset, sequence and counts.
fn finish_prefix<'a,O,R>(origin: Origin, objects: &'a [O], roots: &'a [R],
    marker: Option<(u64,&[u8])>, observed: Counts, digest: [u8;32]) -> (out: Option<Batch<&'a O,&'a R>>)
    ensures out.is_some() == (marker matches Some((offset,m)) && offset == origin.offset && m@ == (Marker {counts: observed, digest}).wire() &&
        observed.sequence != 0 && observed.sequence == origin.sequence &&
        observed.objects == objects.len() && observed.roots == roots.len() && observed.roots > 0),
        out matches Some(batch) ==> {
            let image = batch.contents();
            &&& image.origin == origin
            &&& image.objects.len() == objects.len()
            &&& image.roots.len() == roots.len()
            &&& forall|j:int| 0 <= j < objects.len() ==> *#[trigger] image.objects[j] == objects@[j]
            &&& forall|j:int| 0 <= j < roots.len() ==> *#[trigger] image.roots[j] == roots@[j]
        },
{
    let pending = pending_descriptors(origin,objects,roots);
    let end = match marker {
        Some((offset,m)) => match check_body(m,observed,digest) {
            Some(marker) => Event::Commit {offset,marker}, None => return None,
        },
        None => Event::Tail,
    };
    match tx::advance(pending,end) {
        Ok(Step::Committed(b)) => Some(b),
        _ => None,
    }
}

}
