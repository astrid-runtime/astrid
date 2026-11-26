//! Traverse one stable WAL byte stream with the cursor returned by each physical read.
use crate::{commit_wire::{self, CheckedMarker, Counts}, hosted_wal_physical_model::read_at,
    wal_measured_record::{DataKind,Measured,ObjectEncoding}, wal_measurement,
    wal_physical_wire as physical, wal_record_wire::{self as logical,WalRecordKind}};
use crate::wal_transaction::{advance, Batch, Event, Origin, Step};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
struct Record<'a> {
    next: usize, kind: WalRecordKind, flags:u8, sequence:u64, ordinal:u64, body:&'a [u8],
}

spec fn tag(kind:WalRecordKind) -> u8 {
    match kind {WalRecordKind::Begin=>1,WalRecordKind::Object=>2,WalRecordKind::Root=>3,WalRecordKind::Commit=>4}
}

/// Exact byte interval, including physical checksum and logical header.
#[verifier::opaque]
spec fn at_record(stream:Seq<u8>, at:int, r:Record, limit:u64, checksum:spec_fn(Seq<u8>)->[u8;32]) -> bool {
    let payload = seq![tag(r.kind),r.flags,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(r.sequence)
        + vstd::bytes::spec_u64_to_le_bytes(r.ordinal) + r.body@;
    let h = physical::Envelope {version:if r.flags == 0 {1} else {2},size:payload.len() as u64,checksum:checksum(payload)};
    &&& 0 <= at < r.next <= stream.len()
    &&& r.sequence != 0 && (r.flags == 0 || (r.kind is Object && r.flags == 1))
    &&& payload.len() <= limit
    &&& stream.subrange(at,r.next as int) == h.wire() + payload
    &&& r.next as int == at + physical::WIDTH + logical::HEADER_LEN + r.body.len()
}

fn read_record<'a,H>(stream:&'a [u8],at:usize,limit:u64,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>, hint:Ghost<Option<Record<'a>>>)
    -> (out:Option<Record<'a>>) where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        hint@ matches Some(r) ==> at_record(stream@,at as int,r,limit,checksum@),
    ensures hint@.is_some() ==> out == hint@,
        out matches Some(r) ==> at_record(stream@,at as int,r,limit,checksum@) &&
        at < r.next <= stream.len() && (r.flags == 0 || (r.kind is Object && r.flags == 1)),
{
    proof {
        if let Some(r) = hint@ {
            reveal(at_record);
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            let data = seq![tag(r.kind),r.flags,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(r.sequence)
                + vstd::bytes::spec_u64_to_le_bytes(r.ordinal) + r.body@;
            let e = physical::Envelope {version:if r.flags==0 {1} else {2},size:data.len() as u64,checksum:(checksum@)(data)};
            let h = stream@.subrange(at as int,at as int+52);
            assert(h =~= e.wire());
            assert(h.take(8) =~= physical::MAGIC@);
            assert(h.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(e.size));
            assert(h.skip(20) =~= e.checksum@);
            let span = stream@.subrange(at as int,r.next as int);
            assert(span == e.wire() + data);
            assert(e.wire().len() == 52);
            assert(span.skip(52) =~= data);
            assert(stream@.subrange(at as int+52,r.next as int) =~= span.skip(52));
        }
    }
    let (next,payload,envelope) = read_at(stream,at,limit,hash,checksum)?;
    let (header,body) = logical::split(payload)?;
    proof {
        if let Some(r) = hint@ {
            reveal(at_record);
            assert(header.kind == tag(r.kind));
            assert(header.flags == r.flags);
            assert(header.reserved@ =~= seq![0u8,0u8]);
            assert(header.sequence@ =~= vstd::bytes::spec_u64_to_le_bytes(r.sequence));
            assert(header.ordinal@ =~= vstd::bytes::spec_u64_to_le_bytes(r.ordinal));
            assert(body@ =~= r.body@);
            match r.kind {WalRecordKind::Begin=>{},WalRecordKind::Root=>{},WalRecordKind::Object=>{},WalRecordKind::Commit=>{}}
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        }
    }
    let kind = header.classify().ok()?;
    let sequence = u64::from_le_bytes(header.sequence);
    let ordinal = u64::from_le_bytes(header.ordinal);
    if sequence == 0 || !envelope.accepts(kind,header.flags) { return None; }
    let r = Record {next,kind,flags:header.flags,sequence,ordinal,body};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(header.sequence@ =~= vstd::bytes::spec_u64_to_le_bytes(sequence));
        assert(header.ordinal@ =~= vstd::bytes::spec_u64_to_le_bytes(ordinal));
        assert(header.bytes() + body@ =~= payload@);
        let start = at as int + physical::WIDTH;
        assert(envelope.wire().subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(envelope.size));
        assert(envelope.size == payload.len());
        assert(stream@.subrange(at as int,next as int) =~= envelope.wire() + payload@);
        assert(header.kind == tag(kind)) by { match kind {
            WalRecordKind::Begin=>{},WalRecordKind::Object=>{},WalRecordKind::Root=>{},WalRecordKind::Commit=>{},
        }}
        assert(header.reserved@ =~= seq![0u8,0u8]);
        assert(payload@ =~= seq![tag(kind),r.flags,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(sequence)
            + vstd::bytes::spec_u64_to_le_bytes(ordinal) + body@);
        assert(envelope.version == if r.flags == 0 {1u8} else {2u8});
        reveal(at_record);
        assert(at_record(stream@,at as int,r,limit,checksum@));
    }
    proof {
        if let Some(want) = hint@ {
            assert(body == want.body);
            assert(kind == want.kind) by {match want.kind {WalRecordKind::Begin=>{},WalRecordKind::Root=>{},WalRecordKind::Object=>{},WalRecordKind::Commit=>{}}}
            assert(r == want);
        }
    }
    Some(r)
}

spec fn chunk(r:Record) -> Seq<u8> {
    wal_measurement::digest_header(r.kind,r.flags,r.sequence,r.ordinal,r.body.len() as u64) + r.body@
}

spec fn transcript(records:Seq<Record>) -> Seq<u8> decreases records.len() {
    if records.len() == 0 { Seq::empty() } else { transcript(records.drop_last()) + chunk(records.last()) }
}

spec fn totals(records:Seq<Record>) -> (nat,nat,nat) decreases records.len() {
    if records.len() == 0 { (0,0,0) } else {
        let (objects,roots,bytes) = totals(records.drop_last());
        let r = records.last();
        (objects + (if r.kind is Object {1nat} else {0nat}),
         roots + (if r.kind is Root {1nat} else {0nat}),
         bytes + logical::HEADER_LEN as nat + r.body.len() as nat)
    }
}

#[verifier::opaque]
spec fn data_chain(stream:Seq<u8>, start:usize, records:Seq<Record>, limit:u64,
    checksum:spec_fn(Seq<u8>)->[u8;32]) -> bool
    decreases records.len(),
{
    if records.len() == 0 {false} else {
        let r = records.last();
        if records.len() == 1 {
            r.kind is Begin && r.ordinal == 0 && at_record(stream,start as int,r,limit,checksum)
        } else {
            let before = records.drop_last();
            &&& data_chain(stream,start,before,limit,checksum)
            &&& at_record(stream,before.last().next as int,r,limit,checksum)
            &&& r.sequence == before[0].sequence && r.ordinal == before.len()
            &&& (r.kind is Object || r.kind is Root) && (r.kind is Object ==> totals(before).1 == 0)
        }
    }
}

#[verifier::opaque]
spec fn receipt(stream:Seq<u8>,start:usize,limit:u64,
    checksum:spec_fn(Seq<u8>)->[u8;32],digest:spec_fn(Seq<u8>)->[u8;32],end:usize,checked:CheckedMarker,
    rs:Seq<Record>,commit:Record) -> bool {
    &&& data_chain(stream,start,rs,limit,checksum)
    &&& at_record(stream,rs.last().next as int,commit,limit,checksum) && commit.kind is Commit
    &&& commit.next == end && commit.sequence == rs[0].sequence && commit.ordinal == rs.len()
    &&& checked.marker().wire() == commit.body@ && checked.marker().counts.sequence == commit.sequence
    &&& checked.marker().counts.logical == rs.len() && checked.marker().counts.roots > 0
    &&& checked.marker().counts.objects == totals(rs).0 && checked.marker().counts.roots == totals(rs).1
    &&& checked.marker().counts.bytes == totals(rs).2
    &&& digest(transcript(rs)) == checked.marker().digest
}

fn observe(r:&Record, measured:Measured) -> (out:(Counts,Vec<u8>))
    requires ({let (k,f,o,c,b) = measured.parts(); k == r.kind && f == r.flags &&
        o == r.ordinal && c.sequence == r.sequence && b == r.body}),
    ensures out.0 == measured.parts().3 && out.1@ == chunk(*r),
{
    let collect = |header:&[u8],body:&[u8]| -> (bytes:Vec<u8>) ensures bytes@ == header@ + body@ {
        let mut bytes = Vec::new(); bytes.extend_from_slice(header); bytes.extend_from_slice(body);
        assert(bytes@ =~= header@ + body@); bytes
    };
    let (counts,bytes) = measured.observe(collect);
    proof {
        let h = choose|h:&[u8]| h@ == wal_measurement::digest_header(r.kind,r.flags,r.sequence,r.ordinal,r.body.len() as u64)
            && #[trigger] collect.ensures((h,r.body),bytes);
        assert(collect.ensures((h,r.body),bytes));
    }
    (counts,bytes)
}

/// Proof-only description of a complete transaction. Each state is the
/// mathematical count after the corresponding stored record.
struct Layout<'a> { rows:Seq<Record<'a>>, states:Seq<Counts>, commit:Record<'a> }

spec fn step(r:Record, before:Counts, after:Counts) -> bool {
    &&& before.sequence == r.sequence == after.sequence
    &&& r.ordinal == before.logical && after.logical as int == before.logical as int + 1
    &&& after.bytes as int == before.bytes as int + logical::HEADER_LEN + r.body.len()
    &&& match r.kind {
        WalRecordKind::Object => before.roots == 0 && after.roots == 0 &&
            after.objects as int == before.objects as int + 1,
        WalRecordKind::Root => after.objects == before.objects && after.roots as int == before.roots as int + 1,
        _ => false,
    }
}

#[verifier::opaque]
spec fn complete(layout:Layout, stream:Seq<u8>,start:usize,limit:u64,
    checksum:spec_fn(Seq<u8>)->[u8;32],digest:spec_fn(Seq<u8>)->[u8;32]) -> bool {
    let rows = layout.rows;
    let states = layout.states;
    let begin = rows[0];
    let c = states[0];
    let commit = layout.commit;
    &&& rows.len() > 0 && states.len() == rows.len()
    &&& at_record(stream,start as int,begin,limit,checksum) && begin.kind is Begin && begin.ordinal == 0
    &&& c.sequence == begin.sequence && c.logical == 1 && c.objects == 0 && c.roots == 0
    &&& c.bytes as int == logical::HEADER_LEN as int + begin.body.len()
    &&& forall|i:int| 0 < i < rows.len() ==> at_record(stream,rows[i-1].next as int,
            #[trigger] rows[i],limit,checksum) && step(rows[i],states[i-1],states[i])
    &&& at_record(stream,rows.last().next as int,commit,limit,checksum) && commit.kind is Commit
    &&& states.last().roots > 0 && commit.sequence == states.last().sequence && commit.ordinal == states.last().logical
    &&& commit.body@ == (commit_wire::Marker { counts:states.last(),digest:digest(transcript(rows)) }).wire()
}

proof fn begin_facts(w:Layout,stream:Seq<u8>,start:usize,limit:u64,checksum:spec_fn(Seq<u8>)->[u8;32],digest:spec_fn(Seq<u8>)->[u8;32])
    requires complete(w,stream,start,limit,checksum,digest),
    ensures w.rows.len() > 0 && w.rows.len() == w.states.len(), ({
        let r = w.rows[0]; let c = w.states[0];
        &&& at_record(stream,start as int,r,limit,checksum) && r.kind is Begin && r.ordinal == 0
        &&& c.sequence == r.sequence && c.logical == 1 && c.objects == 0 && c.roots == 0
        &&& c.bytes as int == logical::HEADER_LEN as int + r.body.len()
    }),
{ reveal(complete); }

proof fn next_facts(w:Layout,i:int,stream:Seq<u8>,start:usize,limit:u64,checksum:spec_fn(Seq<u8>)->[u8;32],digest:spec_fn(Seq<u8>)->[u8;32])
    requires complete(w,stream,start,limit,checksum,digest), 0 < i <= w.rows.len(),
    ensures w.rows.len() == w.states.len(),
        i < w.rows.len() ==> at_record(stream,w.rows[i-1].next as int,w.rows[i],limit,checksum) &&
            step(w.rows[i],w.states[i-1],w.states[i]),
        i == w.rows.len() ==> ({
            let c = w.states[i-1]; let r = w.commit;
            &&& at_record(stream,w.rows[i-1].next as int,r,limit,checksum) && r.kind is Commit
            &&& c.roots > 0 && r.sequence == c.sequence && r.ordinal == c.logical
            &&& r.body@ == (commit_wire::Marker {counts:c,digest:digest(transcript(w.rows))}).wire()
        }),
{ reveal(complete); }

spec fn selected(rows:Seq<Record>, kind:WalRecordKind) -> Seq<Record>
    decreases rows.len(),
{
    if rows.len() == 0 { Seq::empty() } else {
        let before = selected(rows.drop_last(),kind);
        if rows.last().kind == kind { before.push(rows.last()) } else { before }
    }
}

spec fn released(scan:Scan,start:usize) -> bool {
    let rows = scan.trace@.0;
    let batch = scan.batch.contents();
    &&& batch.origin.offset == start && batch.origin.sequence == scan.marker.marker().counts.sequence
    &&& batch.objects == selected(rows,WalRecordKind::Object) && batch.roots == selected(rows,WalRecordKind::Root)
}

struct Scan<'a> {
    end:usize, marker:CheckedMarker, batch:Batch<Record<'a>,Record<'a>>, trace:Ghost<(Seq<Record<'a>>,Record<'a>)>,
}

/// A successful traversal binds the checked marker and digest to records read
/// at successive offsets from this stream. No caller-supplied event list or
/// record count controls the loop or chooses the Commit.
#[verifier::rlimit(15)]
fn scan_transaction<'a,H,F>(stream:&'a [u8],start:usize,limit:u64,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F, digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>, witness:Ghost<Option<Layout<'a>>>)
    -> (out:Option<Scan<'a>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:FnOnce(&[u8])->[u8;32],
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        witness@ matches Some(w) ==> complete(w,stream@,start,limit,checksum@,digest@),
    ensures witness@ matches Some(w) ==> out matches Some(scanned) && scanned.end == w.commit.next &&
        scanned.marker.marker() == (commit_wire::Marker {counts:w.states.last(),digest:(digest@)(transcript(w.rows))}),
        out matches Some(scanned) ==> receipt(stream@,start,limit,checksum@,digest@,
        scanned.end,scanned.marker,scanned.trace@.0,scanned.trace@.1) && released(scanned,start),
{
    proof { if let Some(w) = witness@ {begin_facts(w,stream@,start,limit,checksum@,digest@);} }
    let begin = read_record(stream,start,limit,hash,checksum,Ghost(match witness@ {Some(w)=>Some(w.rows[0]),None=>None}))?;
    if !matches!(begin.kind,WalRecordKind::Begin) || begin.ordinal != 0 {return None;}
    let sequence = begin.sequence;
    let mut cursor = begin.next;
    let origin = Origin {sequence,offset:start as u64};
    let mut batch = match advance(None,Event::<Record,Record>::Begin(origin)) {
        Ok(Step::Pending(batch)) => batch, _ => return None,
    };
    let first = Measured::begin(sequence,begin.body).ok()?;
    let (mut counts,mut data) = observe(&begin,first);
    let ghost mut rs = seq![begin];
    assert(rs.drop_last() =~= Seq::<Record>::empty());
    assert(rs.last() == begin);
    assert(data@ =~= chunk(begin));
    reveal_with_fuel(transcript,2);
    reveal_with_fuel(totals,2);
    reveal_with_fuel(selected,2);
    assert(data@ =~= transcript(rs));
    assert(data_chain(stream@,start,rs,limit,checksum@)) by {reveal(data_chain);}
    proof { if let Some(w) = witness@ { assert(rs =~= w.rows.take(1)); } }
    loop
        invariant witness@ matches Some(w) ==> complete(w,stream@,start,limit,checksum@,digest@) &&
                0 < rs.len() <= w.rows.len() && rs == w.rows.take(rs.len() as int) && counts == w.states[rs.len()-1],
            cursor <= stream.len(), rs.len() > 0, cursor == rs.last().next,
            data_chain(stream@,start,rs,limit,checksum@), data@ == transcript(rs),
            counts.objects == totals(rs).0, counts.roots == totals(rs).1, counts.bytes == totals(rs).2,
            batch.contents().origin == origin, origin.offset == start, origin.sequence == sequence,
            batch.contents().objects == selected(rs,WalRecordKind::Object), batch.contents().roots == selected(rs,WalRecordKind::Root),
            batch.contents().objects.len() == counts.objects, batch.contents().roots.len() == counts.roots,
            counts.logical == rs.len(), counts.sequence == sequence == rs[0].sequence,
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
            forall|p:&[u8]| #[trigger] finish.requires((p,)),
            forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        decreases stream.len() - cursor,
    {
        let ghost hint = match witness@ {Some(w)=>Some(if rs.len() == w.rows.len() {w.commit} else {w.rows[rs.len() as int]}),None=>None};
        proof {
            if let Some(w) = witness@ {
                next_facts(w,rs.len() as int,stream@,start,limit,checksum@,digest@);
                assert(rs.last() == w.rows[rs.len()-1]);
                if rs.len() == w.rows.len() { assert(rs =~= w.rows); }
                else { assert(step(w.rows[rs.len() as int],counts,w.states[rs.len() as int])); }
            }
        }
        let r = read_record(stream,cursor,limit,hash,checksum,Ghost(hint))?;
        let body = logical::body_at_position(r.body,r.sequence,r.ordinal,sequence,counts.logical).ok()?;
        let kind = match r.kind {
            WalRecordKind::Begin => return None,
            WalRecordKind::Commit => {
                if counts.roots == 0 {return None;}
                proof {
                    if let Some(w) = witness@ {
                        assert(rs =~= w.rows);
                        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
                        assert(body.len() == 72);
                    }
                }
                let marker = commit_wire::decode(body)?;
                let p = data.as_slice();
                let sum = finish(p);
                proof {
                    if let Some(w) = witness@ {
                        let expected = commit_wire::Marker {counts,digest:sum};
                        assert(finish.ensures((p,),sum));
                        assert(expected.wire() == marker.wire());
                        crate::hosted_wal_model::unique_marker(expected,marker);
                    }
                }
                let compare = || -> (d:[u8;32]) ensures d == sum {sum};
                let checked = marker.confirm(&counts,compare).ok()?;
                assert(compare.ensures((),checked.marker().digest));
                assert(finish.ensures((p,),checked.marker().digest));
                assert(receipt(stream@,start,limit,checksum@,digest@,r.next,checked,rs,r)) by {reveal(receipt);}
                let batch = match advance(Some(batch),Event::Commit {offset:start as u64,marker:checked}) {
                    Ok(Step::Committed(batch)) => batch, _ => return None,
                };
                return Some(Scan {end:r.next,marker:checked,batch,trace:Ghost((rs,r))});
            },
            WalRecordKind::Root => DataKind::Root,
            WalRecordKind::Object => {
                if counts.roots != 0 { return None; }
                DataKind::Object(ObjectEncoding::from_flag(r.flags)?)
            },
        };
        let measured = Measured::append(counts,kind,body).ok()?;
        let (next,part) = observe(&r,measured);
        let event = match kind { DataKind::Object(_) => Event::Object(r), DataKind::Root => Event::Root(r) };
        batch = match advance(Some(batch),event) { Ok(Step::Pending(batch)) => batch, _ => return None };
        counts = next;
        cursor = r.next;
        data.extend_from_slice(&part);
        let ghost extended = rs.push(r);
        assert(extended.drop_last() =~= rs);
        proof { assert(extended.last() == r);
            assert(data_chain(stream@,start,extended,limit,checksum@)) by {reveal(data_chain);} }
        proof {
            if let Some(w) = witness@ {
                assert(extended =~= w.rows.take(extended.len() as int));
            }
            rs = extended;
        }
    }
}

/// The external byte-stream contract needs no record list. A mathematical
/// layout, when one exists, supplies hints only to the verifier.
fn recover<'a,H,F>(stream:&'a [u8],start:usize,limit:u64,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<Scan<'a>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:FnOnce(&[u8])->[u8;32],
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
    ensures (exists|w:Layout| #[trigger] complete(w,stream@,start,limit,checksum@,digest@)) ==> out.is_some(),
        out matches Some(scan) ==> receipt(stream@,start,limit,checksum@,digest@,scan.end,scan.marker,scan.trace@.0,scan.trace@.1) && released(scan,start),
{
    let ghost hint = if exists|w:Layout| #[trigger] complete(w,stream@,start,limit,checksum@,digest@) {
        Some(choose|w:Layout| #[trigger] complete(w,stream@,start,limit,checksum@,digest@))
    } else {None};
    scan_transaction(stream,start,limit,hash,checksum,finish,digest,Ghost(hint))
}

}
