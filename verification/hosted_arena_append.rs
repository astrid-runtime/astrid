//! Read back a selected object from the framed byte stream submitted for append.
use crate::arena_frame::Sink;
use crate::{arena_frame as frame, arena_span, root_wire::Scheme, verified_record as record};
use vstd::prelude::*;

verus! {

/// Check the physical frame domain, format, declared length and digest before replaying its payload.
fn physical_frame<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(header:&[u8;52],magic:[u8;8],version:u16,
    body:&[u8],hash:H,digest:Ghost<spec_fn([u8;8],u64,Seq<u8>)->[u8;32]>) -> (accepted:bool)
    requires forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
        forall|m:[u8;8],n:u64,b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((m,n,b),sum) ==> sum == (digest@)(m,n,b@),
    ensures accepted == (header@ == frame::header_bytes(magic,version,body.len() as u64,
        (digest@)(magic,body.len() as u64,body@))),
{
    let ghost size = body.len() as u64;
    let ghost sum = (digest@)(magic,size,body@);
    let ghost canonical = frame::header_bytes(magic,version,size,sum);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(canonical.take(8) =~= magic@);
        assert(canonical.subrange(8,12) =~= seq![version as u8,(version >> 8) as u8,0u8,0u8]);
        assert(canonical.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(size));
        assert(canonical.subrange(20,52) =~= sum@);
    }
    if !frame::magic_matches(header,magic) {return false;}
    let selected = match frame::decode_header(header,version) {Ok(v)=>v,Err(_)=>return false};
    match frame::check_payload(selected,magic,body,hash) {
        Ok(actual) => {
            assert(selected.payload_len == size);
            assert(header@.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(size));
            assert(header@ =~= canonical) by {
                assert forall|i:int| 0 <= i < 52 implies header@[i] == #[trigger] canonical[i] by {
                    if i < 8 {assert(header@.take(8)[i] == header@[i]);}
                    else if i >= 20 {assert(header@.subrange(20,52)[i-20] == header@[i]);}
                    else if i >= 12 {assert(header@.subrange(12,20)[i-12] == header@[i]);}
                    else {
                        assert(header@[8] == version as u8 && header@[9] == (version >> 8) as u8);
                        assert(header@[10] == 0 && header@[11] == 0);
                        assert(header@.subrange(8,12) =~= canonical.subrange(8,12));
                        assert(header@.subrange(8,12)[i-8] == header@[i]);
                    }
                }
            }
            true
        },
        Err(frame::PayloadError::Length) => {assert(header@ != canonical);false},
        Err(frame::PayloadError::Checksum) => {
            proof {if header@ == canonical {
                assert(selected.payload_len == size);
                assert(selected.checksum@ =~= sum@);
                assert(selected.checksum =~= sum);
                let ghost different = choose|v:[u8;32]| v != selected.checksum &&
                    #[trigger] hash.ensures((magic,selected.payload_len,body),v);
                assert(different == sum);
            }}
            false
        },
    }
}

/// Every accepted root contributes its own complete journal at the same index.
fn legacy_group_journals<'a,P,R:Copy>(group:&'a [crate::root_transition::PreparedRoot<P,R>],index:usize)
    requires index < group.len(),
{
    use crate::root_transition::PreparedRoot;
    let select = |root:&'a PreparedRoot<P,R>| -> (bytes:&'a [u8])
            ensures bytes@ == root.binding().3@, {root.journal().as_slice()};
    let frames = crate::group_frontier::journals(group,select);
    assert(select.ensures((&group@[index as int],),frames@[index as int]));
    assert(frames.len() == group.len());
    assert(frames@[index as int]@ == group@[index as int].binding().3@);
}

/// Locate a root journal entry after an arbitrary coalesced prefix, validate its
/// physical header and checksum, and recover the owner and both root fields.
fn legacy_journal_readback<H:Copy+Fn([u8;8],u64,&[u8])->[u8;32]>(
    mut batch:Vec<u8>,base:u64,magic:[u8;8],version:u16,owner:&[u8],scheme:Scheme,
    expected:Option<crate::root_wire::Root>,replacement:crate::root_wire::Root,
    hash:H,digest:Ghost<spec_fn([u8;8],u64,Seq<u8>)->[u8;32]>,
)
    requires owner.len() < u64::MAX,
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
        forall|m:[u8;8],n:u64,b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((m,n,b),sum) ==> sum == (digest@)(m,n,b@),
{
    use crate::root_wire as wire;
    let payload = wire::encode(owner,scheme,expected,replacement).unwrap();
    let prefix = batch.len();
    let ghost original = batch@;
    let Some(location) = frame::extend_batch(&mut batch,base,magic,version,&payload,hash) else {
        assert(base as int + prefix > u64::MAX || payload.len() > u64::MAX ||
            prefix as int + frame::WIDTH + payload.len() > isize::MAX);
        assert(batch@ == original);
        return;
    };
    assert(prefix as int + frame::WIDTH + payload.len() <= isize::MAX);
    assert(location.offset == base as int + prefix && location.payload_len == payload.len());
    assert(location.checksum == (digest@)(magic,payload.len() as u64,payload@));
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(frame::header_bytes(magic,version,location.payload_len,location.checksum).len() == 52);
    let start = (location.offset - base) as usize;
    assert(start == prefix && batch.len() == start + 52 + payload.len());
    let mut header = [0u8;52];
    header.copy_from_slice(&batch[start..start+52]);
    let body = &batch[start+52..];
    assert(batch@.take(start as int) =~= original);
    assert(header@ =~= frame::header_bytes(magic,version,location.payload_len,location.checksum));
    assert(body@ =~= payload@);
    let valid = physical_frame(&header,magic,version,body,hash,digest);
    assert(valid);
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(owner.len() as u64));
    let Ok((name,mut cursor)) = wire::read_owner(body) else {assert(false);return;};
    assert(name@ =~= owner@);
    let ghost at = cursor as int;
    assert(body@.skip(at) =~= wire::prior(expected,scheme) + replacement.wire(scheme));
    assert(wire::tail(body@,at,scheme,expected,replacement));
    let Ok((prior,next)) = wire::read_tail(body,&mut cursor,scheme) else {assert(false);return;};
    proof {wire::unique_tail(body@,at,scheme,prior,next,expected,replacement);}
    assert(wire::same_expected(prior,expected) && wire::same(next,replacement));
}

/// Normal frames advance the cursor to their full end; oversize frames retain their interior classification.
fn frame_extent(at:u64,end:u64,len:u64,limit:u64) -> (result:(u8,u64))
    ensures ({
        let next = at as int + 52 + len;
        result == if len > limit {(if next <= end {1u8} else {2u8},0u64)}
            else if next > u64::MAX {(3u8,0u64)} else if next > end {(4u8,0u64)}
            else {(0u8,next as u64)}
    }),
{
    use crate::frame_repair::{extent,Extent};
    match extent(at,end,len,limit) {
        Extent::Complete(n) => (0,n),
        Extent::Oversize {interior:true} => (1,0),Extent::Oversize {interior:false} => (2,0),
        Extent::Overflow => (3,0),Extent::Incomplete => (4,0),
    }
}

/// A captured committed range cannot probe, resize, or flush even when its first frame is damaged.
fn preserve_committed<M:crate::frame_repair::Medium>(media:&mut M,start:u64,end:u64,physical:u64,at:u64,
    damage:crate::frame_repair::Damage) -> (rejected:bool)
    requires start <= at < end <= physical,
    ensures rejected, final(media).calls() == old(media).calls(), final(media).bytes() == old(media).bytes(),
        final(media).durable() == old(media).durable(),
{
    use crate::frame_repair as r;
    let w = r::window(physical,r::Bound::Committed {start,end}).unwrap();
    matches!(r::repair(media,at,w.end,w.protected,damage),Ok(r::Outcome::Reject))
}

/// A live scan may discard an incomplete payload only beyond the protected prefix.
/// The native adapter reports success only after synchronizing the new length on the same handle.
fn incomplete_payload<M:crate::frame_repair::Medium>(media:&mut M,physical:u64,protected:u64,at:u64,len:u64,limit:u64)
    -> (out:Result<bool,crate::frame_repair::Error<M::Error>>)
    requires protected <= physical, at < physical, len <= limit, physical < at as int + 52 + len <= u64::MAX,
        physical <= old(media).bytes().len(),
    ensures ({
        let calls = old(media).calls();
        let resized = calls.push(crate::frame_repair::Event::Resize(at));
        &&& match out {
            Ok(false) => at < protected && final(media).calls() == calls && final(media).bytes() == old(media).bytes(),
            Ok(true) => at >= protected && final(media).calls() == resized.push(crate::frame_repair::Event::Flush)
                && final(media).durable() == old(media).bytes().take(at as int) && final(media).bytes() == final(media).durable(),
            Err(crate::frame_repair::Error::Resize(_)) => at >= protected && final(media).calls() == resized,
            Err(crate::frame_repair::Error::Flush(_)) => at >= protected && final(media).calls() == resized.push(crate::frame_repair::Event::Flush),
            Err(_) => false,
        }
    }),
{
    use crate::frame_repair as r;
    let w = r::window(physical,r::Bound::Live(protected)).unwrap();
    match r::extent(at,w.end,len,limit) {
        r::Extent::Incomplete => {},
        _ => {assert(false);return Ok(false);},
    }
    match r::repair(media,at,w.end,w.protected,r::Damage::Incomplete) {
        Ok(r::Outcome::Reject) => Ok(false),Ok(r::Outcome::Repaired) => Ok(true),Err(e) => Err(e),
    }
}

/// If the later-frame probe finds a frame or fails, recovery leaves the media unchanged.
fn preserve_later_frame<M:crate::frame_repair::Medium>(media:&mut M,at:u64,end:u64,protected:u64,known_interior:bool)
    -> (refused:bool)
    requires protected <= at < end, !old(media).probe_result(at,Ok(false)),
    ensures refused, final(media).calls() == if known_interior {old(media).calls()} else {old(media).calls().push(crate::frame_repair::Event::Probe(at))},
        final(media).bytes() == old(media).bytes(), final(media).durable() == old(media).durable(),
{
    use crate::frame_repair as r;
    match r::repair(media,at,end,protected,r::Damage::Suspect {known_interior}) {
        Ok(r::Outcome::Reject) | Err(r::Error::Probe(_)) => true,_ => false,
    }
}

struct Buffer(Vec<u8>);

impl frame::Sink for Buffer {
    type Error = ();
    closed spec fn sent(&self) -> Seq<u8> {self.0@}
    closed spec fn failed(_before:Seq<u8>,_batch:Seq<frame::PreparedFrame>,_e:()) -> bool {false}

    fn write_chunk(&mut self,batch:&[frame::PreparedFrame]) -> Result<(),()> {
        let mut i = 0usize;
        while i < batch.len()
            invariant i <= batch.len(), self.0@ == old(self).0@ + frame::prefix(batch@,i as nat),
            decreases batch.len()-i,
        {
            let (header,payload) = batch[i].parts();
            self.0.extend_from_slice(header);
            self.0.extend_from_slice(payload);
            i = i.saturating_add(1);
        }
        Ok(())
    }
}

proof fn interval(fs:Seq<frame::PreparedFrame>,row:nat)
    requires row < fs.len(),
    ensures ({
        let wire = frame::prefix(fs,fs.len());
        let start = frame::prefix(fs,row).len() as int;
        start + fs[row as int].wire().len() <= wire.len() && wire.subrange(start,start+fs[row as int].wire().len()) == fs[row as int].wire()
    }),
{
    frame::segment(fs,row+1,fs.len());
    assert(frame::prefix(fs,row+1) == frame::prefix(fs,row) + fs[row as int].wire());
    let start = frame::prefix(fs,row).len() as int;
    assert(frame::prefix(fs,fs.len()).subrange(start,start+fs[row as int].wire().len()) =~= fs[row as int].wire());
}

/// The consumer accepts an arbitrary selected location in a multi-chunk
/// batch, including when the original file starts at a nonzero offset.
#[verifier::spinoff_prover]
#[verifier::rlimit(20)]
fn read_leaf<H:Fn([u8;8],u64,&[u8])->[u8;32],I:Fn(&crate::ObjectRecord)->[u8;32]>(
    fs:&[frame::PreparedFrame], row:usize, base:u64, batch_size:usize,
    magic:[u8;8],version:u16,id:crate::ObjectId,scheme:Scheme,hash:H,identify:I,
) -> (out:Option<crate::ObjectRecord>)
    requires row < fs.len(), batch_size > 0, base as int + frame::prefix(fs@,fs@.len()).len() <= u64::MAX,
        ({
            let f = fs@[row as int];
            let bytes = f.body();
            &&& f.wire() == frame::header_bytes(magic,version,bytes.len() as u64,f.sum())+bytes
            &&& record::tag(bytes,0,scheme) && record::leaf_body(bytes,40) && id.digest() == bytes.subrange(8,40)
            &&& forall|p:&[u8],s:[u8;32]| p@ == bytes && #[trigger] hash.ensures((magic,bytes.len() as u64,p),s) ==> s == f.sum()
            &&& forall|r:&crate::ObjectRecord,d:[u8;32]| record::record_at(bytes,40,scheme,*r) &&
                #[trigger] identify.ensures((r,),d) ==> d@ == id.digest()
        }),
        forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
    ensures out matches Some(r) && record::record_at(fs@[row as int].body(),40,scheme,r),
{
    let mut sink = Buffer(Vec::new());
    let rows = match frame::append(&mut sink,fs,base,Vec::new(),batch_size) {
        Ok(rows) => rows,
        Err(frame::AppendError::Overflow) => {assert(false); return None;},
        Err(frame::AppendError::Write(e)) => {
            let ghost pair = choose|pair:(int,int)| frame::failed_step::<Buffer>(Seq::empty(),fs@,batch_size,e,pair.0,pair.1);
            assert(false);
            return None;
        },
    };
    let loc = rows[row];
    let ghost f = fs@[row as int];
    let ghost start = frame::prefix(fs@,row as nat).len() as int;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        interval(fs@,row as nat);
        assert(f.wire().len() == 52+f.body().len());
        frame::segment(fs@,(row+1) as nat,fs@.len());
        assert(start+f.wire().len() <= sink.0.len());
    }
    let bytes = arena_span::frame(&sink.0,base,loc.offset,loc.payload_len)?;
    proof {
        assert(bytes@ =~= f.wire());
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.take(8) =~= magic@);
        assert(bytes@.subrange(8,10) =~= seq![version as u8,(version >> 8) as u8]);
        assert(bytes@.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(loc.payload_len));
        assert(bytes@.subrange(20,52) =~= f.sum()@);
        assert(bytes@.skip(52) =~= f.body());
    }
    let p = arena_span::payload(bytes,magic,version,loc.payload_len,loc.checksum,u64::MAX,hash).ok()?;
    record::confirmed(p,scheme,id,identify).ok()
}

type Observation<'a> = (crate::ObjectId,frame::ArenaLocation,crate::ObjectRecord,&'a [u8]);

/// Observe ordered delivery with the actual frame authenticator as decoder.
/// All observations borrow payloads from the same physical span.
#[verifier::loop_isolation(false)]
pub(super) fn observe_span<'a,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&crate::ObjectRecord)->[u8;32]+Copy>(
    rows:&[(crate::ObjectId,frame::ArenaLocation)],span:&'a [u8],base:u64,format:crate::indexed_frame::Format,
    hash:H,identify:I,reject:Option<u64>) -> (result:Result<Vec<Observation<'a>>,bool>)
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
    ensures result matches Ok(trace) ==> trace.len() == rows.len() &&
        forall|j:int| 0 <= j < rows.len() ==> {
            let (id,loc,r,p) = #[trigger] trace@[j];
            id == rows@[j].0 && loc == rows@[j].1 &&
            p@ == span@.subrange(loc.offset as int-base+52,loc.offset as int-base+52+loc.payload_len) &&
            record::record_at(p@,40,format.scheme,r) && id.digest()==p@.subrange(8,40)
        },
{
    use crate::indexed_frame::{deliver,delivered,read};
    let decode = |id:crate::ObjectId,loc:frame::ArenaLocation| -> (out:Result<(crate::ObjectRecord,&'a [u8]),bool>)
        ensures match out {
            Ok((r,p)) => p@ == span@.subrange(loc.offset as int-base+52,loc.offset as int-base+52+loc.payload_len) &&
                record::record_at(p@,40,format.scheme,r) && id.digest()==p@.subrange(8,40),
            Err(e) => !e,
        },
    {
        match read(span,base,loc,id,format,hash,identify) {
            Ok((r,p)) => {
                assert(p@ =~= span@.subrange(loc.offset as int-base+52,loc.offset as int-base+52+loc.payload_len));
                Ok((r,p))
            },
            Err(_) => Err(false),
        }
    };
    let accept = |trace:Vec<Observation<'a>>,id:crate::ObjectId,loc:frame::ArenaLocation,r:crate::ObjectRecord,p:&'a [u8]| -> (out:Result<Vec<Observation<'a>>,bool>)
        ensures if Some(loc.offset)==reject {out == Err(true)} else {
            out matches Ok(t) && t@ == trace@.push((id,loc,r,p))
        },
    {
        if Some(loc.offset)==reject {return Err(true);}
        let mut trace = trace;
        trace.push((id,loc,r,p));
        Ok(trace)
    };
    let start = Vec::new();
    let result = deliver(rows,start,decode,accept);
    match result {
        Ok(trace) => {
            let ghost states = choose|x:Seq<Vec<Observation<'a>>>| #[trigger] delivered(rows@,x,decode,accept) &&
                x.first()==start && x.last()==trace;
            let mut i = 0usize;
            while i < rows.len()
                invariant 0 <= i <= rows.len(),states[i as int]@.len()==i,
                    forall|j:int| 0 <= j < i ==> {
                        let (id,loc,r,p) = #[trigger] states[i as int]@[j];
                        let at = loc.offset as int-base+52;
                        id == rows@[j].0 && loc == rows@[j].1 && Some(loc.offset)!=reject &&
                        p@ == span@.subrange(at,at+loc.payload_len) && record::record_at(p@,40,format.scheme,r) &&
                        id.digest()==p@.subrange(8,40)
                    },
                    delivered(rows@,states,decode,accept),
                decreases rows.len()-i,
            {
                proof {
                    let (id,loc) = rows@[i as int];
                    assert(crate::indexed_frame::sent(rows@[i as int],states[i as int],states[i as int+1],decode,accept));
                    let (r,p) = choose|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((id,loc),Ok((r,p))) &&
                        accept.ensures((states[i as int],id,loc,r,p),Ok(states[i as int+1]));
                    let at = loc.offset as int-base;
                    assert(p@ =~= span@.subrange(at+52,at+52+loc.payload_len));
                    assert(states[i as int+1]@ == states[i as int]@.push((id,loc,r,p)));
                };
                i = i.saturating_add(1);
            }
            assert(trace.len() == rows.len());
            assert forall|j:int| 0 <= j < rows.len() implies {
                let (id,loc,r,p) = #[trigger] trace@[j];
                p@ == span@.subrange(loc.offset as int-base+52,loc.offset as int-base+52+loc.payload_len) &&
                id == rows@[j].0 && loc == rows@[j].1 && Some(loc.offset)!=reject &&
                record::record_at(p@,40,format.scheme,r) && id.digest()==p@.subrange(8,40)
            } by {};
            Ok(trace)
        },
        Err(e) => { proof {
            assert(exists|i:int,states:Seq<Vec<Observation<'a>>>| 0 <= i < rows.len() &&
                #[trigger] delivered(rows@.take(i),states,decode,accept) && states.first()==start &&
                (decode.ensures((rows@[i].0,rows@[i].1),Err(e)) ||
                    exists|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) &&
                        accept.ensures((states.last(),rows@[i].0,rows@[i].1,r,p),Err(e))));
            let (i,states) = choose|i:int,states:Seq<Vec<Observation<'a>>>| 0 <= i < rows.len() &&
                #[trigger] delivered(rows@.take(i),states,decode,accept) && states.first()==start &&
                (decode.ensures((rows@[i].0,rows@[i].1),Err(e)) ||
                    exists|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) &&
                        accept.ensures((states.last(),rows@[i].0,rows@[i].1,r,p),Err(e)));
            if e {assert(Some(rows@[i].1.offset)==reject);}
        } Err(e)},
    }
}

type IndexedRow = (crate::ObjectId,frame::ArenaLocation);

proof fn dispatched_prefix<V:Fn(Vec<IndexedRow>,&[IndexedRow],u64,u64)->Result<Vec<IndexedRow>,Option<Vec<IndexedRow>>>>(
    rows:Seq<IndexedRow>,end:int,start:Vec<IndexedRow>,trace:Vec<IndexedRow>,limit:u64,visit:V)
    requires 0 <= end <= rows.len(),crate::indexed_frame::dispatched(rows,end,start,trace,limit,visit),
        forall|before:Vec<IndexedRow>,part:&[IndexedRow],base:u64,size:u64,after:Vec<IndexedRow>|
            #[trigger] visit.ensures((before,part,base,size),Ok(after)) ==> after@ == before@ + part@,
    ensures trace@ == start@ + rows.take(end),
    decreases end,
{
    if end == 0 { assert(rows.take(0) =~= Seq::empty()); return; }
    let (lo,prior,part,size) = choose|lo:int,prior:Vec<IndexedRow>,part:&[IndexedRow],size:u64|
        crate::indexed_frame::batch(rows,lo,end,limit) && part@ == rows.subrange(lo,end) &&
        size as int == crate::indexed_frame::frame_end(rows[end-1].1)-rows[lo].1.offset &&
        #[trigger] visit.ensures((prior,part,rows[lo].1.offset,size),Ok(trace)) &&
        crate::indexed_frame::dispatched(rows,lo,start,prior,limit,visit);
    dispatched_prefix(rows,lo,start,prior,limit,visit);
    assert(trace@ =~= start@ + rows.take(end));
}

/// Observe the production dispatcher's physical requests. The reader rejects
/// any mismatched address or extent and may independently fail at one offset.
fn observe_dispatch(rows:&[IndexedRow],target:u64,limit:u64,fault:Option<u64>) -> (out:Result<Vec<IndexedRow>,Vec<IndexedRow>>)
    requires forall|i:int| 0 <= i < rows.len() ==> #[trigger] crate::indexed_frame::frame_end(rows@[i].1) <= u64::MAX,
        forall|i:int| 0 <= i < rows.len() ==> #[trigger] rows@[i].1.payload_len <= limit,
    ensures match out {
        Ok(trace) => trace@ == rows@,
        Err(prefix) => prefix.len() < rows.len() && prefix@ == rows@.take(prefix.len() as int) &&
            fault == Some(rows@[prefix.len() as int].1.offset),
    },
{
    use crate::indexed_frame::{dispatch,dispatched,frame_end,DispatchError};
    let visit = |before:Vec<IndexedRow>,part:&[IndexedRow],base:u64,size:u64| -> (out:Result<Vec<IndexedRow>,Option<Vec<IndexedRow>>>)
        ensures match out {
            Ok(after) => after@ == before@ + part@,
            Err(Some(prefix)) => prefix == before && fault == Some(base),
            Err(None) => part.len()==0 || base != part@[0].1.offset ||
                base as int + size != frame_end(part@[part.len()-1].1),
        },
    {
        if part.is_empty() || part[0].1.offset != base ||
            part[part.len().saturating_sub(1)].1.end() != base.checked_add(size) {return Err(None);}
        if fault == Some(base) {return Err(Some(before));}
        let mut trace = before;
        let mut n = 0usize;
        while n < part.len()
            invariant n <= part.len(), trace@ == before@ + part@.take(n as int),
            decreases part.len()-n,
        {
            trace.push(part[n]);
            assert(trace@ =~= before@ + part@.take(n as int+1));
            n = n.saturating_add(1);
        }
        assert(part@.take(n as int) =~= part@);
        Ok(trace)
    };
    let start = Vec::new();
    match dispatch(rows,target,limit,start,visit) {
        Ok(trace) => { proof {
            dispatched_prefix(rows@,rows.len() as int,start,trace,limit,visit);
            assert(rows@.take(rows.len() as int) =~= rows@);
            assert(trace@ =~= rows@);
        } Ok(trace)},
        Err(DispatchError::Visit(e)) => { proof {
            let (lo,prior) = choose|lo:int,state:Vec<IndexedRow>| 0 <= lo < rows.len() &&
                #[trigger] dispatched(rows@,lo,start,state,limit,visit) &&
                crate::indexed_frame::visit_failed(rows@,lo,state,limit,visit,e);
            dispatched_prefix(rows@,lo,start,prior,limit,visit);
            assert(prior@ =~= rows@.take(lo));
            assert(e == Some(prior) && fault == Some(rows@[lo].1.offset));
            assert(prior.len() == lo);
        } Err(e.unwrap())},
        Err(_) => { assert(false); Err(Vec::new()) },
    }
}

/// Sorting preserves every occurrence before positional dispatch.
fn ordered_dispatch(requested:&[IndexedRow],target:u64,limit:u64,fault:Option<u64>)
    -> (out:Result<Vec<IndexedRow>,(Vec<IndexedRow>,Vec<IndexedRow>)>)
    requires forall|i:int| 0 <= i < requested.len() ==> #[trigger] crate::indexed_frame::frame_end(requested@[i].1) <= u64::MAX,
        forall|i:int| 0 <= i < requested.len() ==> #[trigger] requested@[i].1.payload_len <= limit,
    ensures ({
        let trace = match out {Ok(t)=>t,Err((t,_))=>t};
        &&& trace@.to_multiset() == requested@.to_multiset()
        &&& forall|i:int,j:int| #![trigger trace@[i],trace@[j]] 0 <= i < j < trace.len()
            ==> trace@[i].1.offset <= trace@[j].1.offset
        &&& out matches Err((table,prefix)) ==> {
            let n = prefix.len() as int;
            &&& n < table.len() && fault == Some(table@[n].1.offset)
            &&& prefix@ == table@.take(n)
            &&& exists|j:int| 0 <= j < requested.len() && #[trigger] requested@[j] == table@[n]
            &&& prefix@.to_multiset().add(table@.skip(n).to_multiset()) == requested@.to_multiset()
        }
    }),
{
    use crate::indexed_frame::frame_end;
    let rows = crate::indexed_frame::ordered(requested);
    proof {
        rows@.to_multiset_ensures();
        requested@.to_multiset_ensures();
        assert forall|i:int| 0 <= i < rows.len() implies
            frame_end(#[trigger] rows@[i].1) <= u64::MAX && rows@[i].1.payload_len <= limit by {
            let row = rows@[i];
            assert(rows@.contains(row));
            assert(rows@.to_multiset().count(row) > 0);
            assert(requested@.to_multiset().count(row) > 0);
            assert(requested@.contains(row));
            let k = choose|k:int| 0 <= k < requested.len() && requested@[k] == row;
            assert(frame_end(requested@[k].1) <= u64::MAX && requested@[k].1.payload_len <= limit);
        }
    }
    match observe_dispatch(&rows,target,limit,fault) {
        Ok(trace) => Ok(trace),
        Err(seen) => {
            let n = seen.len();
            proof {
                assert(rows@.contains(rows@[n as int]));
                assert(rows@.to_multiset().count(rows@[n as int]) > 0);
                assert(requested@.contains(rows@[n as int]));
                let prefix = rows@.take(n as int);
                let suffix = rows@.skip(n as int);
                assert(prefix + suffix =~= rows@);
                vstd::seq_lib::lemma_multiset_commutative(prefix,suffix);
            }
            Err((rows,seen))
        },
    }
}

/// Each successful positional read can cover exactly the next range of
/// frame indices. Induct across those ranges for any representable table.
fn partition_reads(rows:&[(crate::ObjectId,frame::ArenaLocation)],target:u64)
    requires forall|i:int| 0 <= i < rows.len() ==> #[trigger] crate::indexed_frame::frame_end(rows@[i].1) <= u64::MAX,
{
    use crate::indexed_frame::{coalesced,frame_end};
    let mut first = 0;
    while first < rows.len()
        invariant first <= rows.len(),
            forall|i:int| 0 <= i < rows.len() ==> #[trigger] frame_end(rows@[i].1) <= u64::MAX,
        decreases rows.len()-first,
    {
        let batch = coalesced(rows,first,target);
        assert(batch.is_some());
        let (end,len) = batch.unwrap();
        let base = rows[first].1.offset;
        assert(first < end <= rows.len());
        assert(base as int + len == frame_end(rows@[end as int-1].1));
        assert forall|i:int| first <= i < end implies base <= #[trigger] rows@[i].1.offset &&
            frame_end(rows@[i].1) <= base as int + len by {};
        assert forall|i:int| first < i < end implies #[trigger] rows@[i].1.offset == frame_end(rows@[i-1].1) by {};
        let ghost cap = if target as int > frame_end(rows@[first as int].1)-base {target as int} else {frame_end(rows@[first as int].1)-base};
        assert(len <= cap);
        proof { if end < rows.len() && rows@[end as int].1.offset == base as int + len {
            assert(frame_end(rows@[end as int].1)-base > cap);
        } }
        first = end;
    }
    assert(first == rows.len());
}

/// The native preload loop exits on an empty batch. Every pending object
/// must then already be resident. Every nonempty batch selects only the
/// indexed locations for unresolved members of this exact frontier.
fn preload_wave(frontier:&std::collections::BTreeSet<crate::ObjectId>,
    loaded:&std::collections::BTreeMap<crate::ObjectId,crate::ObjectRecord>,
    index:&std::collections::BTreeMap<crate::ObjectId,frame::ArenaLocation>)
    requires vstd::std_specs::btree::btree_set_inv(frontier), vstd::std_specs::btree::btree_map_inv(loaded),
        vstd::std_specs::btree::btree_map_inv(index), vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),
        vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
{
    match crate::journal_preload::requests(frontier,loaded,index) {
        Ok(rows) => {
            let ghost ids = rows@.map(|_,row:(crate::ObjectId,frame::ArenaLocation)| row.0);
            proof {
                assert(ids.no_duplicates());
                ids.to_set_ensures();
                assert(ids.to_set() =~= frontier@.difference(loaded@.dom()));
                if rows.len() == 0 {
                    assert(ids.len() == 0);
                    assert forall|k:crate::ObjectId| frontier@.contains(k) implies loaded@.contains_key(k) by {
                        if !loaded@.contains_key(k) {
                            assert(ids.to_set().contains(k));
                            assert(ids.contains(k));
                        }
                    }
                }
                assert forall|i:int| 0 <= i < rows.len() implies
                    index@.contains_key(#[trigger] rows@[i].0) && index@[rows@[i].0] == rows@[i].1 by {};
            }
        },
        Err(missing) => {
            assert(frontier@.contains(missing) && !loaded@.contains_key(missing) && !index@.contains_key(missing));
        },
    }
}

/// Deliver an interior indexed frame to recovery and follow only owning
/// references of the exact record whose digest was checked against the index.
fn indexed_preload<H:FnOnce([u8;8],u64,&[u8])->[u8;32],I:FnOnce(&crate::ObjectRecord)->[u8;32]>(
    loaded:&mut std::collections::BTreeMap<crate::ObjectId,crate::ObjectRecord>,
    pending:&mut std::collections::BTreeSet<crate::ObjectId>,data:&[u8],base:u64,loc:frame::ArenaLocation,
    id:crate::ObjectId,magic:[u8;8],version:u16,limit:u64,scheme:Scheme,hash:H,identify:I)
    requires vstd::std_specs::btree::btree_map_inv(old(loaded)),vstd::std_specs::btree::btree_set_inv(old(pending)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
{
    use crate::indexed_frame::{read,Error};
    let ghost at = loc.offset as int - base;
    let ghost bytes = data@.subrange(at,at+52+loc.payload_len);
    let ghost body = bytes.skip(52);
    let ghost earlier = loaded@;
    let ghost queue = pending@;
    let result = read(data,base,loc,id,crate::indexed_frame::Format {magic,version,limit,scheme},hash,identify);
    let ghost fits = base <= loc.offset && loc.payload_len as int + 52 <= u64::MAX &&
        at+52+loc.payload_len <= data.len();
    assert((result matches Err(Error::Bounds)) == !fits);
    proof {
        if fits && loc.payload_len <= limit &&
            bytes == frame::header_bytes(magic,version,loc.payload_len,loc.checksum) + body &&
            record::tag(body,0,scheme) && record::leaf_body(body,40) && id.digest() == body.subrange(8,40) &&
            (forall|p:&[u8],s:[u8;32]| p@==body && #[trigger] hash.ensures((magic,loc.payload_len,p),s) ==> s==loc.checksum) &&
            (forall|r:&crate::ObjectRecord,d:[u8;32]| record::record_at(body,40,scheme,*r) &&
                #[trigger] identify.ensures((r,),d) ==> d@==id.digest())
        {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(bytes.take(8) =~= magic@);
            assert(bytes.subrange(8,12) =~= seq![version as u8,(version >> 8) as u8,0u8,0u8]);
            assert(bytes.subrange(8,10) =~= seq![version as u8,(version >> 8) as u8]);
            assert(bytes.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(loc.payload_len));
            assert(bytes.subrange(20,52) =~= loc.checksum@);
            assert(result.is_ok());
        }
    }
    match result {
        Ok((r,p))=>{
            assert(p@ =~= data@.subrange(at+52,at+52+loc.payload_len));
            assert(loc.payload_len <= limit && magic@ == bytes.take(8) && bytes.subrange(20,52) == loc.checksum@);
            assert(bytes.subrange(8,10) == seq![version as u8,(version >> 8) as u8] && bytes[10]==0 && bytes[11]==0);
            assert(arena_span::declared(bytes) == loc.payload_len && hash.ensures((magic,loc.payload_len,p),loc.checksum));
            assert(record::tag(body,0,scheme) && id.digest() == body.subrange(8,40));
            crate::journal_preload::accept(loaded,pending,id,r);
            assert(loaded@ == earlier.insert(id,r) && record::record_at(body,40,scheme,loaded@[id]));
            assert(exists|d:[u8;32]| d@==id.digest() && #[trigger] identify.ensures((&loaded@[id],),d));
            assert(pending@ == queue.union(crate::closure_walk::children(loaded@[id].contents().3).difference(earlier.dom())));
        },
        Err(Error::Record(record::Error::Identity))=>{
            assert(exists|r:crate::ObjectRecord,d:[u8;32]| d@!=id.digest() && record::record_at(body,40,scheme,r)
                && #[trigger] identify.ensures((&r,),d));
        },
        Err(Error::Record(record::Error::Identifier))=>{assert(id.digest()!=body.subrange(8,40));},
        Err(Error::Envelope(arena_span::Error::Limit(n)))=>{assert(n==arena_span::declared(bytes) && n>limit);},
        Err(_)=>{},
    }
    proof { if result.is_err() {assert(loaded@ == earlier && pending@ == queue);} }
}

/// Instantiate both ends of write/read with the same profile of hash
/// callbacks. An earlier unrelated frame occupies a separate output chunk.
fn prepare_pair<H:Copy+Fn([u8;8],u64,&[u8])->[u8;32],I:Fn(&crate::ObjectRecord)->[u8;32]>(
    other:Vec<u8>,leaf:Vec<u8>,base:u64,magic:[u8;8],version:u16,id:crate::ObjectId,scheme:Scheme,
    hash:H,identify:I,Ghost(digest):Ghost<spec_fn([u8;8],Seq<u8>)->[u8;32]>,
) -> (out:Option<crate::ObjectRecord>)
    requires base as int+104+other.len()+leaf.len() <= u64::MAX,
        record::tag(leaf@,0,scheme),record::leaf_body(leaf@,40),id.digest() == leaf@.subrange(8,40),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|r:&crate::ObjectRecord,d:[u8;32]| record::record_at(leaf@,40,scheme,*r) &&
            #[trigger] identify.ensures((r,),d) ==> d@ == id.digest(),
        forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
        forall|n:u64,p:&[u8],d:[u8;32]| #[trigger] hash.ensures((magic,n,p),d) && n == p.len() ==> d == digest(magic,p@),
    ensures out matches Some(r) && record::record_at(leaf@,40,scheme,r),
{
    let first = frame::PreparedFrame::prepare(magic,version,other,hash)?;
    let second = frame::PreparedFrame::prepare(magic,version,leaf,hash)?;
    let frames = [first,second];
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        reveal_with_fuel(frame::prefix,3);
        assert(frame::prefix(frames@,2).len() == 104+other.len()+leaf.len());
        let p = choose|p:&[u8]| p@ == leaf@ && #[trigger] hash.ensures((magic,leaf.len() as u64,p),second.sum());
        assert(hash.ensures((magic,leaf.len() as u64,p),second.sum()));
        assert(second.sum() == digest(magic,p@));
        assert forall|q:&[u8],d:[u8;32]| q@ == leaf@ && #[trigger] hash.ensures((magic,leaf.len() as u64,q),d)
            implies d == second.sum() by {assert(d == digest(magic,q@));}
    }
    read_leaf(&frames,1,base,1,magic,version,id,scheme,hash,identify)
}

/// The staging tables consume the returned append locations. On failure
/// before publication they retain their old contents.
fn publish_selected<S:frame::Sink,K:Ord+Copy>(
    sink:&mut S,frames:&[frame::PreparedFrame],ids:&[K],row:usize,base:u64,
    index:&mut std::collections::BTreeMap<K,frame::ArenaLocation>,delta:&mut Vec<(K,frame::ArenaLocation)>,
) -> (out:Result<(),frame::AppendError<S::Error>>)
    requires ids.len() == frames.len(), row < ids.len(),
        forall|i:int| row < i < ids.len() ==> #[trigger] ids@[i] != ids@[row as int],
        vstd::std_specs::btree::btree_map_inv(old(index)),vstd::laws_cmp::obeys_cmp::<K>(),
        vstd::laws_cmp::obeys_cmp_concrete_eq::<K>(),
    ensures match out {
        Ok(()) => {
            let key = ids@[row as int];
            let loc = final(index)@[key];
            let at = frame::prefix(frames@,row as nat).len();
            let start = old(sink).sent().len()+at;
            let f = frames@[row as int];
            &&& final(index)@.contains_key(key) && loc.offset == base as int + at
            &&& loc.payload_len == f.body().len() && loc.checksum == f.sum()
            &&& final(delta).len() == old(delta).len() + frames.len()
            &&& final(delta)@[old(delta).len()+row] == (key,loc)
            &&& final(sink).sent().subrange(start as int,start as int+f.wire().len()) == f.wire()
        },
        Err(_) => final(index)@ == old(index)@ && final(delta)@ == old(delta)@,
    },
{
    let rows = frame::append(sink,frames,base,Vec::new(),32)?;
    let ghost before = index@;
    let ok = crate::arena_index::publish_batch(index,delta,ids,&rows);
    assert(ok);
    proof {
        crate::hosted_arena_placement::last_placement(before,ids@,rows@,row as int,ids@.len());
        interval(frames@,row as nat);
        let start = old(sink).sent().len()+frame::prefix(frames@,row as nat).len();
        let total = frame::prefix(frames@,frames@.len());
        let off = frame::prefix(frames@,row as nat).len() as int;
        let width = frames@[row as int].wire().len();
        assert(sink.sent() == old(sink).sent()+total);
        assert(sink.sent().subrange(start as int,start as int+width) =~= total.subrange(off,off+width));
    }
    Ok(())
}

/// Feed the persisted location from one delta row back into the recovery map.
fn reload_row(recovered:&mut std::collections::BTreeMap<crate::ObjectId,frame::ArenaLocation>,
    scheme:Scheme, key:crate::ObjectId, loc:frame::ArenaLocation, frontier:u64) -> (ok:bool)
    requires vstd::std_specs::btree::btree_map_inv(old(recovered)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        scheme.algorithm@ != seq![0u8,0u8], scheme.construction@ != seq![0u8,0u8],
    ensures ok == (loc.offset as int + frame::WIDTH + loc.payload_len <= frontier &&
            (!old(recovered)@.contains_key(key) || old(recovered)@[key] == loc)),
        final(recovered)@ == if ok {old(recovered)@.insert(key,loc)} else {old(recovered)@},
{
    let mut bytes = Vec::new();
    let raw = *key.as_bytes();
    record::append_identity(&mut bytes,scheme,raw);
    loc.encode(&mut bytes);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(loc.wire().len() == 48);
        assert(bytes@.subrange(0,40) =~= record::wire(scheme,raw));
        record::tag_written(bytes@,0,scheme,raw);
        assert(bytes@.subrange(0,4) =~= scheme.algorithm@ + scheme.construction@);
    }
    let mut cursor = 0;
    let Ok((decoded_key,parsed)) = crate::checkpoint_key::row(&bytes,&mut cursor,scheme,None)
        else {assert(false);return false;};
    proof {
        crate::ObjectId::same_digest(key,decoded_key);
        assert(bytes@.subrange(40,88) =~= loc.wire());
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    }
    proof {
        assert(loc.wire().take(8) =~= vstd::bytes::spec_u64_to_le_bytes(loc.offset));
        assert(parsed.wire().take(8) =~= vstd::bytes::spec_u64_to_le_bytes(parsed.offset));
        assert(loc.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(loc.payload_len));
        assert(parsed.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(parsed.payload_len));
        assert(loc.wire().skip(16) =~= loc.checksum@);
        assert(parsed.wire().skip(16) =~= parsed.checksum@);
        assert(parsed.checksum == loc.checksum);
        assert(parsed == loc);
    }
    let Some(end) = parsed.end() else {return false;};
    if end > frontier {return false;}
    crate::arena_index::restore_location(recovered,decoded_key,parsed)
}

/// Recover an arbitrary named row, including an interior row. Later names
/// must be distinct from the requested name.
proof fn selected_mapping(bytes:Seq<u8>,start:int,count:nat,selected:nat,
    expected:crate::ObjectId,map:Map<crate::ObjectId,frame::ArenaLocation>)
    requires selected < count, crate::checkpoint_key::mapped(bytes,start,count,map),
        expected.digest() == bytes.subrange(start + selected*88 + 8,start + selected*88 + 40),
        forall|j:int| selected < j < count ==> #[trigger] bytes.subrange(start+j*88+8,start+j*88+40) != expected.digest(),
    ensures map.contains_key(expected), map[expected].wire() == bytes.subrange(start+selected*88+40,start+selected*88+88),
    decreases count,
{
    let at = start + (count-1)*88;
    let (prior,id,loc) = choose|p:Map<crate::ObjectId,frame::ArenaLocation>,id:crate::ObjectId,loc:frame::ArenaLocation|
        crate::checkpoint_key::mapped(bytes,start,(count-1) as nat,p) &&
        id.digest() == bytes.subrange(at+8,at+40) && loc.wire() == bytes.subrange(at+40,at+88) &&
        map == #[trigger] p.insert(id,loc);
    if selected == count-1 {
        crate::ObjectId::same_digest(expected,id);
    } else {
        assert(bytes.subrange(at+8,at+40) != expected.digest());
        selected_mapping(bytes,start,(count-1) as nat,selected,expected,prior);
    }
}

proof fn increasing(bytes:Seq<u8>,start:int,count:nat,i:int,j:int,scheme:Scheme)
    requires 0 <= start, 0 <= i < j < count,
        forall|h:int| 0 <= h < count ==> #[trigger] crate::checkpoint_key::ordered_row(bytes,start,h,scheme),
    ensures crate::ObjectId::digest_before(bytes.subrange(start+i*88+8,start+i*88+40),bytes.subrange(start+j*88+8,start+j*88+40)),
    decreases j-i,
{
    assert(crate::checkpoint_key::ordered_row(bytes,start,i,scheme));
    assert(crate::checkpoint_key::ordered_row(bytes,start,j,scheme));
    if i+1 < j {
        increasing(bytes,start,count,i,j-1,scheme);
        assert(crate::checkpoint_key::ordered_row(bytes,start,j-1,scheme));
        crate::ObjectId::digest_order_transitive(bytes.subrange(start+i*88+8,start+i*88+40),
            bytes.subrange(start+(j-1)*88+8,start+(j-1)*88+40),bytes.subrange(start+j*88+8,start+j*88+40));
    }
}

fn recover_selected(bytes:&[u8],start:usize,count:usize,selected:usize,scheme:Scheme,expected:crate::ObjectId)
    -> (out:Option<frame::ArenaLocation>)
    requires start <= bytes.len(), selected < count,
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        expected.digest() == bytes@.subrange(start as int + selected as int*88 + 8,start as int + selected as int*88 + 40),
    ensures out.is_some() == (forall|i:int| 0 <= i < count ==> #[trigger] crate::checkpoint_key::ordered_row(bytes@,start as int,i,scheme)),
        out matches Some(loc) ==> loc.wire() == bytes@.subrange(start as int+selected as int*88+40,start as int+selected as int*88+88),
{
    let mut cursor = start;
    let map = crate::checkpoint_key::rows(bytes,&mut cursor,count,scheme).ok()?;
    proof {
        assert forall|j:int| selected < j < count implies #[trigger] bytes@.subrange(start as int+j*88+8,start as int+j*88+40) != expected.digest() by {
            increasing(bytes@,start as int,count as nat,selected as int,j,scheme);
        }
        selected_mapping(bytes@,start as int,count as nat,selected as nat,expected,map@);
    }
    map.get(&expected).copied()
}

/// Decode the first of two writer-produced rows at a nonzero cursor.
fn checkpoint_pair(first:crate::ObjectId,second:crate::ObjectId,a:frame::ArenaLocation,b:frame::ArenaLocation,
    scheme:Scheme) -> (out:Option<frame::ArenaLocation>)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        scheme.algorithm@ != seq![0u8,0u8], scheme.construction@ != seq![0u8,0u8],
    ensures out.is_some() == crate::ObjectId::digest_before(first.digest(),second.digest()),
        out matches Some(loc) ==> loc.wire() == a.wire(),
{
    let mut bytes = Vec::new();
    bytes.push(0);
    let x = *first.as_bytes();
    let y = *second.as_bytes();
    record::append_identity(&mut bytes,scheme,x);
    a.encode(&mut bytes);
    record::append_identity(&mut bytes,scheme,y);
    b.encode(&mut bytes);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(1,41) =~= record::wire(scheme,x));
        assert(bytes@.subrange(89,129) =~= record::wire(scheme,y));
        record::tag_written(bytes@,1,scheme,x);
        record::tag_written(bytes@,89,scheme,y);
        assert(bytes@.subrange(1,5) =~= scheme.algorithm@ + scheme.construction@);
        assert(bytes@.subrange(89,93) =~= scheme.algorithm@ + scheme.construction@);
        assert(bytes@.subrange(41,89) =~= a.wire());
        assert(crate::checkpoint_key::ordered_row(bytes@,1,0,scheme));
        assert(crate::checkpoint_key::ordered_row(bytes@,1,1,scheme) == crate::ObjectId::digest_before(first.digest(),second.digest()));
        if crate::ObjectId::digest_before(first.digest(),second.digest()) {
            assert forall|i:int| 0 <= i < 2 implies #[trigger] crate::checkpoint_key::ordered_row(bytes@,1,i,scheme) by {
                assert(i==0 || i==1);
            }
        }
    }
    recover_selected(&bytes,1,2,0,scheme,first)
}

/// Replay a selected row from the actual append delta. The restored position
/// addresses the same submitted interval, even when the arena began nonempty.
fn publish_and_reload<S:frame::Sink>(
    sink:&mut S,frames:&[frame::PreparedFrame],ids:&[crate::ObjectId],row:usize,base:u64,scheme:Scheme,
    live:&mut std::collections::BTreeMap<crate::ObjectId,frame::ArenaLocation>,delta:&mut Vec<(crate::ObjectId,frame::ArenaLocation)>,
    recovered:&mut std::collections::BTreeMap<crate::ObjectId,frame::ArenaLocation>,frontier:u64,
) -> (out:Result<bool,frame::AppendError<S::Error>>)
    requires ids.len() == frames.len(), row < ids.len(),
        forall|i:int| row < i < ids.len() ==> #[trigger] ids@[i] != ids@[row as int],
        vstd::std_specs::btree::btree_map_inv(old(live)),vstd::std_specs::btree::btree_map_inv(old(recovered)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        scheme.algorithm@ != seq![0u8,0u8], scheme.construction@ != seq![0u8,0u8],
    ensures match out {
        Ok(ok) => {
            let key = ids@[row as int];
            let loc = final(live)@[key];
            let at = frame::prefix(frames@,row as nat).len();
            let start = old(sink).sent().len() + at;
            let f = frames@[row as int];
            &&& ok == (base as int + at + frame::WIDTH + f.body().len() <= frontier &&
                (!old(recovered)@.contains_key(key) || old(recovered)@[key] == loc))
            &&& final(recovered)@ == if ok {old(recovered)@.insert(key,loc)} else {old(recovered)@}
            &&& loc.offset == base as int + at && loc.payload_len == f.body().len() && loc.checksum == f.sum()
            &&& final(sink).sent().subrange(start as int,start as int+f.wire().len()) == f.wire()
        },
        Err(_) => final(recovered)@ == old(recovered)@,
    },
{
    let prior = delta.len();
    publish_selected(sink,frames,ids,row,base,live,delta)?;
    let (key,loc) = delta[prior + row];
    Ok(reload_row(recovered,scheme,key,loc,frontier))
}

/// Connect the production vector builder and partial-write driver. The native
/// cursor is required to start on the supplied slice array in array order.
fn submit_vectors<'a,P:crate::arena_vectors::Part<'a>,C:crate::arena_vectors::Cursor,F:FnOnce(Vec<P>)->C>(
    batch:&'a [frame::PreparedFrame],make:F,Ghost(initial):Ghost<Seq<u8>>,
) -> (out:Option<(C,bool)>)
    requires forall|v:Vec<P>| #[trigger] make.requires((v,)),
        forall|v:Vec<P>,c:C| #[trigger] make.ensures((v,),c) ==> c.sent() == initial &&
            c.remaining() == crate::arena_vectors::flatten(v@,v@.len()),
    ensures out matches Some((c,success)) ==> {
        let bytes = frame::prefix(batch@,batch@.len());
        &&& success ==> c.sent() == initial + bytes
        &&& exists|n:int| 0 <= n <= bytes.len() && c.sent() == initial+bytes.take(n) && c.remaining() == bytes.skip(n)
    },
{
    let vectors = crate::arena_vectors::vectors(batch)?;
    let mut cursor = make(vectors);
    let completed = crate::arena_vectors::transmit(&mut cursor).is_ok();
    Some((cursor,completed))
}

/// A writer that accepts at most one header and one payload byte. A later
/// chunk can fail after an earlier one succeeded, or during the first frame.
struct Cut(Vec<u8>);

impl frame::Sink for Cut {
    type Error = ();
    closed spec fn sent(&self) -> Seq<u8> {self.0@.take(if self.0.len() > 53 {53} else {self.0.len() as int})}
    closed spec fn failed(before:Seq<u8>,batch:Seq<frame::PreparedFrame>,_e:()) -> bool {
        before.len()+frame::prefix(batch,batch.len()).len() > 53
    }
    fn write_chunk(&mut self,batch:&[frame::PreparedFrame]) -> Result<(),()> {
        let mut chunk = Buffer(Vec::new());
        chunk.write_chunk(batch)?;
        let written = self.0.len().min(53);
        self.0.truncate(written);
        let available = 53usize.saturating_sub(written);
        let n = available.min(chunk.0.len());
        self.0.extend_from_slice(&chunk.0[..n]);
        assert(self.sent() =~= old(self).sent()+chunk.0@.take(n as int));
        if n == chunk.0.len() {Ok(())} else {Err(())}
    }
}

/// No locations are returned for the failed append. Even when a previous
/// chunk was accepted, every submitted byte belongs to the same batch prefix.
fn interrupted_append(frames:&[frame::PreparedFrame],base:u64) -> (bytes:Vec<u8>)
    requires frame::prefix(frames@,frames@.len()).len() > 53,
        base as int+frame::prefix(frames@,frames@.len()).len() <= u64::MAX,
    ensures bytes.len() <= 53 && bytes@ == frame::prefix(frames@,frames@.len()).take(bytes.len() as int),
{
    let mut cut = Cut(Vec::new());
    let result = frame::append(&mut cut,frames,base,Vec::new(),1);
    assert(result matches Err(frame::AppendError::Write(_)));
    let n = cut.0.len().min(53);
    cut.0.truncate(n);
    cut.0
}

}
