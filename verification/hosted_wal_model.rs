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

fn writer_marker_is_readable(marker: Marker) -> (accepted: Option<CheckedMarker>)
    requires marker.counts.sequence != 0,
    ensures accepted matches Some(m) && m.marker() == marker,
{
    let bytes = marker.encode();
    let accepted = check_body(&bytes,marker.counts,marker.digest);
    accepted
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

verus! {

/// Independent mathematical sum over a prefix of stored records. Object bytes
/// here are the compressed representation when compression was selected.
spec fn totals(records: Seq<(crate::wal_measurement::Entry,u8,&[u8])>) -> (nat,nat,nat)
    decreases records.len(),
{
    if records.len() == 0 { (0,0,0) } else {
        let (objects,roots,bytes) = totals(records.drop_last());
        let (kind,_,body) = records.last();
        (objects + (if kind is Object {1nat} else {0nat}),
         roots + (if kind is Root {1nat} else {0nat}),
         bytes + crate::wal_record_wire::HEADER_LEN as nat + body.len() as nat)
    }
}

spec fn fits(begin: &[u8], prefix: Seq<(crate::wal_measurement::Entry,u8,&[u8])>) -> bool {
    let (objects,roots,bytes) = totals(prefix);
    &&& 1 + prefix.len() <= u64::MAX
    &&& objects <= u64::MAX && roots <= u64::MAX
    &&& crate::wal_record_wire::HEADER_LEN as int + begin.len() + bytes <= u64::MAX
}

spec fn transcript(begin: &[u8], sequence:u64, records: Seq<(crate::wal_measurement::Entry,u8,&[u8])>) -> Seq<u8>
    decreases records.len(),
{
    use crate::wal_record_wire::WalRecordKind;
    if records.len() == 0 {
        crate::wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64) + begin@
    } else {
        let (entry,flags,body) = records.last();
        let (kind,flags) = match entry {
            crate::wal_measurement::Entry::Object => (WalRecordKind::Object,flags),
            crate::wal_measurement::Entry::Root => (WalRecordKind::Root,0u8),
        };
        transcript(begin,sequence,records.drop_last()) +
            crate::wal_measurement::digest_header(kind,flags,sequence,records.len() as u64,body.len() as u64) + body@
    }
}

/// Measure arbitrary prefixes with the production writer/scanner transitions,
/// then serialize and confirm the marker using this exact observation.
fn measured_marker<H: Fn([u8;8],u64,&[u8])->[u8;32] + Copy, F: FnOnce(&[u8]) -> [u8;32]>(sequence: u64, begin: &[u8],
    records: &[(crate::wal_measurement::Entry,u8,&[u8])], hash:H, checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>, finish:F)
    -> (result: Option<CheckedMarker>)
    requires sequence != 0, forall|data:&[u8]| #[trigger] finish.requires((data,)),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((crate::physical_wire::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        begin.len() as int + 72 <= usize::MAX,
        forall|j:int| 0 <= j < records.len() ==> ({
            let (entry,flags,body) = #[trigger] records@[j];
            body.len() as int + 72 <= usize::MAX && (entry is Object ==> flags <= 1)
        }),
    ensures result.is_some() == (forall|j:int| 0 <= j <= records.len() ==>
            #[trigger] fits(begin,records@.take(j))),
        result matches Some(marker) ==> {
        let (objects,roots,bytes) = totals(records@);
        let c = marker.marker().counts;
        &&& c.sequence == sequence && c.logical as int == 1 + records.len()
        &&& c.objects == objects && c.roots == roots
        &&& c.bytes as int == crate::wal_record_wire::HEADER_LEN as int + begin.len() + bytes
        &&& exists|data:&[u8]| data@ == transcript(begin,sequence,records@) && #[trigger] finish.ensures((data,),marker.marker().digest)
    },
{
    let (_,mut data,mut counts) = crate::hosted_wal_binding::stored_record(None,sequence,begin,&[],&[],u64::MAX,hash,checksum)?;
    assert(fits(begin,records@.take(0)));
    assert(data@ =~= transcript(begin,sequence,records@.take(0)));
    let mut i = 0;
    while i < records.len()
        invariant data@ == transcript(begin,sequence,records@.take(i as int)),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((crate::physical_wire::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|j:int| 0 <= j < records.len() ==> ({
            let (entry,flags,body) = #[trigger] records@[j];
            body.len() as int + 72 <= usize::MAX && (entry is Object ==> flags <= 1)
        }),
            forall|data:&[u8]| #[trigger] finish.requires((data,)), i <= records.len(), counts.sequence == sequence,
            counts.logical as int == 1 + i,
            forall|j:int| 0 <= j <= i ==> #[trigger] fits(begin,records@.take(j)),
            ({ let (o,r,b) = totals(records@.take(i as int));
               counts.objects == o && counts.roots == r &&
               counts.bytes as int == crate::wal_record_wire::HEADER_LEN as int + begin.len() + b }),
        decreases records.len() - i,
    {
        let (kind,flags,body) = records[i];
        proof {
            let next = records@.take(i as int + 1);
            assert(next.drop_last() =~= records@.take(i as int));
            assert(next.last() == (kind,flags,body));
        }
        let entry = match kind {
            crate::wal_measurement::Entry::Object => crate::wal_measured_record::DataKind::Object(crate::wal_measured_record::ObjectEncoding::from_flag(flags)?),
            crate::wal_measurement::Entry::Root => crate::wal_measured_record::DataKind::Root,
        };
        let (_,chunk,next) = match crate::hosted_wal_binding::stored_record(Some((counts,entry)),sequence,body,&[],&[],u64::MAX,hash,checksum) {
            Some(result) => result,
            None => { assert(!fits(begin,records@.take(i as int + 1))); return None; },
        };
        counts = next;
        data.extend_from_slice(&chunk);
        assert(fits(begin,records@.take(i as int + 1)));
        i += 1;
    }
    assert(records@.take(i as int) =~= records@);
    let bytes = data.as_slice();
    let digest = finish(bytes);
    assert(finish.ensures((bytes,),digest));
    let marker = writer_marker_is_readable(Marker { counts,digest });
    assert(bytes@ == transcript(begin,sequence,records@));
    assert(finish.ensures((bytes,),marker.unwrap().marker().digest));
    marker
}

}
