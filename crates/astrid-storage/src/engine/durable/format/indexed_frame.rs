//! Authenticate one selected object inside a coalesced arena read.
use super::{
    ArenaLocation, ObjectId, ObjectRecord, arena_span as span, root_wire::Scheme,
    verified_record as record,
};
use vstd::prelude::*;

verus! {
pub(super) enum Error { Bounds, Envelope(span::Error), Record(record::Error<record::BodyError>) }

pub(super) open spec fn fits(data:Seq<u8>,base:u64,loc:ArenaLocation) -> bool {
    base <= loc.offset && loc.payload_len as int + 52 <= u64::MAX &&
        loc.offset as int - base + 52 + loc.payload_len <= data.len()
}

pub(super) open spec fn envelope<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    bytes:Seq<u8>,magic:[u8;8],version:u16,loc:ArenaLocation,limit:u64,hash:H,e:span::Error) -> bool {
    match e {
        span::Error::Truncated=>bytes.len()<52,
        span::Error::Magic=>bytes.take(8)!=magic@,
        span::Error::Version=>bytes.subrange(8,10)!=seq![version as u8,(version >> 8) as u8],
        span::Error::Reserved=>bytes[10]!=0 || bytes[11]!=0,
        span::Error::Limit(n)=>n==span::declared(bytes) && n>limit,
        span::Error::Length=>loc.payload_len!=span::declared(bytes),
        span::Error::Payload=>bytes.len()!=52+loc.payload_len as int,
        span::Error::Checksum=>bytes.subrange(20,52)!=loc.checksum@ ||
            exists|p:&[u8],s:[u8;32]| p@==bytes.skip(52) && s!=loc.checksum && #[trigger] hash.ensures((magic,loc.payload_len,p),s),
    }
}

#[derive(Clone,Copy)]
pub(super) struct Format {
    pub(super) magic:[u8;8], pub(super) version:u16, pub(super) limit:u64, pub(super) scheme:Scheme,
}

pub(super) open spec fn frame_end(loc:ArenaLocation) -> int {
    loc.offset as int + super::arena_frame::WIDTH + loc.payload_len
}

/// Pick the maximal contiguous prefix starting at first. A single frame may
/// exceed the coalescing target. Overflow on an adjacent candidate is fatal.
pub(super) fn coalesced(rows:&[(ObjectId,ArenaLocation)],first:usize,target:u64)
    -> (out:Option<(usize,u64)>)
    requires first < rows.len(),
    ensures ({
        let base = rows@[first as int].1.offset;
        let cap = if target as int > frame_end(rows@[first as int].1)-base {
            target as int
        } else {frame_end(rows@[first as int].1)-base};
        match out {
            Some((end,len)) => {
                &&& first < end <= rows.len()
                &&& len as int == frame_end(rows@[end as int-1].1)-base && len <= cap
                &&& forall|i:int| first <= i < end ==> base <= #[trigger] rows@[i].1.offset &&
                    frame_end(rows@[i].1) <= base as int + len <= u64::MAX
                &&& forall|i:int| first < i < end ==> #[trigger] rows@[i].1.offset == frame_end(rows@[i-1].1)
                &&& end < rows.len() ==> rows@[end as int].1.offset != base as int + len ||
                    frame_end(rows@[end as int].1)-base > cap
            },
            None => exists|i:int| first <= i < rows.len() && #[trigger] frame_end(rows@[i].1) > u64::MAX &&
                (i == first || rows@[i].1.offset == frame_end(rows@[i-1].1)),
        }
    }),
{
    let initial = rows[first].1;
    let start = initial.offset;
    let Some(mut stop) = initial.end() else {
        assert(frame_end(rows@[first as int].1) > u64::MAX);
        return None;
    };
    let cap = target.max(stop.saturating_sub(start));
    let mut end = first.saturating_add(1);
    loop
        invariant first < end <= rows.len(), start == rows@[first as int].1.offset,
            stop == frame_end(rows@[end as int-1].1), start <= stop, stop-start <= cap,
            cap == if target as int > frame_end(rows@[first as int].1)-start {target as int} else {frame_end(rows@[first as int].1)-start},
            forall|i:int| first <= i < end ==> start <= #[trigger] rows@[i].1.offset && frame_end(rows@[i].1) <= stop,
            forall|i:int| first < i < end ==> #[trigger] rows@[i].1.offset == frame_end(rows@[i-1].1),
        decreases rows.len()-end,
    {
        if end == rows.len() {return Some((end,stop.saturating_sub(start)));}
        let loc = rows[end].1;
        if loc.offset != stop {return Some((end,stop.saturating_sub(start)));}
        let Some(candidate) = loc.end() else {
            assert(frame_end(rows@[end as int].1) > u64::MAX);
            return None;
        };
        if candidate.saturating_sub(start) > cap {return Some((end,stop.saturating_sub(start)));}
        stop = candidate;
        end = end.saturating_add(1);
    }
}

type Row = (ObjectId,ArenaLocation);

/// Order whole index entries by physical offset, retaining duplicate requests.
#[verifier::loop_isolation(false)]
pub(super) fn ordered(rows:&[Row]) -> (sorted:Vec<Row>)
    ensures sorted@.to_multiset() == rows@.to_multiset(), sorted.len() == rows.len(),
        forall|i:int,j:int| #![trigger sorted@[i],sorted@[j]]
            0 <= i < j < sorted.len() ==> sorted@[i].1.offset <= sorted@[j].1.offset,
{
    let offset = |row:&Row| -> (key:u64) ensures key == row.1.offset { row.1.offset };
    let mut entries = Vec::with_capacity(rows.len());
    while entries.len() < rows.len()
        invariant entries.len() <= rows.len(), entries@ == rows@.take(entries.len() as int),
            forall|i:int| 0 <= i < entries.len() ==> offset.ensures((#[trigger] &rows@[i],),rows@[i].1.offset),
        decreases rows.len()-entries.len(),
    {
        let row = &rows[entries.len()];
        let key = offset(row);
        assert(offset.ensures((&rows@[entries.len() as int],),rows@[entries.len() as int].1.offset));
        entries.push((row.0,ArenaLocation {offset:key,..row.1}));
        assert(entries@ =~= rows@.take(entries.len() as int));
    }
    assert(entries@ =~= rows@);
    entries.as_mut_slice().sort_unstable_by_key(offset);
    proof {
        assert(entries@.to_multiset() == rows@.to_multiset());
        rows@.to_multiset_ensures();
        entries@.to_multiset_ensures();
        assert forall|i:int| 0 <= i < entries.len() implies offset.ensures((#[trigger] &entries@[i],),entries@[i].1.offset) by {
            let row = entries@[i];
            assert(entries@.contains(row));
            assert(entries@.to_multiset().count(row) > 0);
            assert(rows@.to_multiset().count(row) > 0);
            assert(rows@.contains(row));
            let k = choose|k:int| 0 <= k < rows.len() && rows@[k] == row;
            assert(offset.ensures((&rows@[k],),rows@[k].1.offset));
        }
        assert forall|i:int,j:int| #![trigger entries@[i],entries@[j]]
            0 <= i < j < entries.len() implies entries@[i].1.offset <= entries@[j].1.offset by {
            assert(vstd::std_specs::slice::key_le(offset,entries@[i],entries@[j]));
        }
    }
    entries
}

pub(super) enum DispatchError<E> { Limit(ArenaLocation), Overflow, Visit(E) }

pub(super) open spec fn batch(rows:Seq<Row>,lo:int,hi:int,limit:u64) -> bool {
    &&& 0 <= lo < hi <= rows.len()
    &&& rows[lo].1.payload_len <= limit
    &&& frame_end(rows[hi-1].1) <= u64::MAX
    &&& forall|i:int| lo < i < hi ==> #[trigger] rows[i].1.offset == frame_end(rows[i-1].1)
}

pub(super) open spec fn dispatched<S,E,V:Fn(S,&[Row],u64,u64)->Result<S,E>>(
    rows:Seq<Row>,end:int,initial:S,state:S,limit:u64,visit:V) -> bool
    decreases end,
{
    if end <= 0 {end == 0 && state == initial} else {
        exists|lo:int,prior:S,part:&[Row],size:u64| batch(rows,lo,end,limit) &&
            part@ == rows.subrange(lo,end) && size as int == frame_end(rows[end-1].1)-rows[lo].1.offset &&
            #[trigger] visit.ensures((prior,part,rows[lo].1.offset,size),Ok(state)) &&
            dispatched(rows,lo,initial,prior,limit,visit)
    }
}

pub(super) open spec fn visit_failed<S,E,V:Fn(S,&[Row],u64,u64)->Result<S,E>>(
    rows:Seq<Row>,lo:int,state:S,limit:u64,visit:V,error:E) -> bool {
    exists|hi:int,part:&[Row],addr:u64,size:u64| #[trigger] batch(rows,lo,hi,limit) && addr == rows[lo].1.offset &&
        part@ == rows.subrange(lo,hi) && size as int == frame_end(rows[hi-1].1)-rows[lo].1.offset &&
        #[trigger] visit.ensures((state,part,addr,size),Err(error))
}

/// Select each range before invoking the positional reader for that range.
pub(super) fn dispatch<S,E,V:Fn(S,&[Row],u64,u64)->Result<S,E>>(rows:&[Row],target:u64,limit:u64,
    initial:S,visit:V) -> (out:Result<S,DispatchError<E>>)
    requires forall|lo:int,hi:int,s:S,p:&[Row],n:u64| #[trigger] batch(rows@,lo,hi,limit) &&
            #[trigger] dispatched(rows@,lo,initial,s,limit,visit) && p@ == rows@.subrange(lo,hi) &&
            n as int == frame_end(rows@[hi-1].1)-rows@[lo].1.offset ==>
            #[trigger] visit.requires((s,p,rows@[lo].1.offset,n)),
    ensures match out {
        Ok(s) => dispatched(rows@,rows.len() as int,initial,s,limit,visit),
        Err(e) => exists|lo:int,state:S| 0 <= lo < rows.len() &&
            #[trigger] dispatched(rows@,lo,initial,state,limit,visit) && match e {
                DispatchError::Limit(loc) => loc == rows@[lo].1 && loc.payload_len > limit,
                DispatchError::Overflow => exists|i:int| lo <= i < rows.len() && #[trigger] frame_end(rows@[i].1) > u64::MAX,
                DispatchError::Visit(error) => visit_failed(rows@,lo,state,limit,visit,error),
            },
    },
{
    let mut first = 0;
    let mut state = initial;
    while first < rows.len()
        invariant first <= rows.len(), dispatched(rows@,first as int,initial,state,limit,visit),
            forall|lo:int,hi:int,s:S,p:&[Row],n:u64| #[trigger] batch(rows@,lo,hi,limit) &&
            #[trigger] dispatched(rows@,lo,initial,s,limit,visit) && p@ == rows@.subrange(lo,hi) &&
            n as int == frame_end(rows@[hi-1].1)-rows@[lo].1.offset ==>
            #[trigger] visit.requires((s,p,rows@[lo].1.offset,n)),
        decreases rows.len()-first,
    {
        let loc = rows[first].1;
        if loc.payload_len > limit { return Err(DispatchError::Limit(loc)); }
        let Some((end,size)) = coalesced(rows,first,target) else {return Err(DispatchError::Overflow);};
        let part = &rows[first..end];
        let ghost prior = state;
        assert(batch(rows@,first as int,end as int,limit));
        assert(visit.requires((state,part,loc.offset,size)));
        state = match visit(state,part,loc.offset,size) {
            Ok(next) => next,
            Err(error) => {
                assert(part@ == rows@.subrange(first as int,end as int));
                assert(visit.ensures((prior,part,rows@[first as int].1.offset,size),Err(error)));
                assert(visit_failed(rows@,first as int,prior,limit,visit,error));
                return Err(DispatchError::Visit(error));
            },
        };
        assert(dispatched(rows@,end as int,initial,state,limit,visit));
        first = end;
    }
    Ok(state)
}

pub(super) open spec fn sent<'a,S,E,D:Fn(ObjectId,ArenaLocation)->Result<(ObjectRecord,&'a [u8]),E>,
    A:Fn(S,ObjectId,ArenaLocation,ObjectRecord,&'a [u8])->Result<S,E>>(
    row:Row,before:S,after:S,decode:D,accept:A) -> bool {
    exists|r:ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((row.0,row.1),Ok((r,p))) &&
        accept.ensures((before,row.0,row.1,r,p),Ok(after))
}

pub(super) open spec fn delivered<'a,S,E,D:Fn(ObjectId,ArenaLocation)->Result<(ObjectRecord,&'a [u8]),E>,
    A:Fn(S,ObjectId,ArenaLocation,ObjectRecord,&'a [u8])->Result<S,E>>(
    rows:Seq<Row>,states:Seq<S>,decode:D,accept:A) -> bool {
    &&& states.len() == rows.len()+1
    &&& forall|i:int| #![trigger rows[i]] 0 <= i < rows.len() ==> sent(rows[i],states[i],states[i+1],decode,accept)
}

/// Thread the visitor through the decoded rows in order. Failure stops
/// delivery at the first unsuccessful decode or visitor invocation.
pub(super) fn deliver<'a,S,E,D:Fn(ObjectId,ArenaLocation)->Result<(ObjectRecord,&'a [u8]),E>,
    A:Fn(S,ObjectId,ArenaLocation,ObjectRecord,&'a [u8])->Result<S,E>>(
    rows:&[Row],initial:S,decode:D,accept:A) -> (out:Result<S,E>)
    requires forall|id:ObjectId,loc:ArenaLocation| #[trigger] decode.requires((id,loc)),
        forall|i:int,states:Seq<S>,r:ObjectRecord,p:&'a [u8]| 0 <= i < rows.len() &&
            states.first()==initial && #[trigger] delivered(rows@.take(i),states,decode,accept) &&
            #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) ==>
            accept.requires((states.last(),rows@[i].0,rows@[i].1,r,p)),
    ensures match out {
        Ok(s) => exists|states:Seq<S>| #[trigger] delivered(rows@,states,decode,accept) &&
            states.first()==initial && states.last()==s,
        Err(e) => exists|i:int,states:Seq<S>| 0 <= i < rows.len() &&
            #[trigger] delivered(rows@.take(i),states,decode,accept) && states.first()==initial &&
            (decode.ensures((rows@[i].0,rows@[i].1),Err(e)) ||
                exists|r:ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) &&
                    accept.ensures((states.last(),rows@[i].0,rows@[i].1,r,p),Err(e))),
    },
{
    let mut state = initial;
    let mut i = 0;
    let ghost mut states = seq![initial];
    while i < rows.len()
        invariant i <= rows.len(), delivered(rows@.take(i as int),states,decode,accept),
            forall|id:ObjectId,loc:ArenaLocation| #[trigger] decode.requires((id,loc)),
            forall|i:int,states:Seq<S>,r:ObjectRecord,p:&'a [u8]| 0 <= i < rows.len() &&
            states.first()==initial && #[trigger] delivered(rows@.take(i),states,decode,accept) &&
            #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) ==>
            accept.requires((states.last(),rows@[i].0,rows@[i].1,r,p)),
            states.first()==initial, states.last()==state,
        decreases rows.len()-i,
    {
        let (id,location) = rows[i];
        let (r,p) = decode(id,location)?;
        assert(accept.requires((state,id,location,r,p)));
        state = accept(state,id,location,r,p)?;
        proof {
            let next = states.push(state);
            let prefix = rows@.take(i as int+1);
            assert forall|j:int| #![trigger prefix[j]] 0 <= j < prefix.len() implies
                sent(prefix[j],next[j],next[j+1],decode,accept) by {
                if j < i {
                    assert(rows@.take(i as int)[j] == prefix[j]);
                    assert(next[j+1] == states[j+1]);
                } else {
                    assert(prefix[j] == (id,location));
                    assert(next[j] == states.last() && next[j+1] == state);
                }
            }
            assert(delivered(prefix,next,decode,accept));
            states = next;
        }
        i = i.saturating_add(1);
    }
    assert(rows@.take(i as int) =~= rows@);
    Ok(state)
}

pub(super) fn read<H:FnOnce([u8;8],u64,&[u8])->[u8;32],I:FnOnce(&ObjectRecord)->[u8;32]>(
    data:&[u8],base:u64,loc:ArenaLocation,id:ObjectId,format:Format,hash:H,identify:I) -> (out:Result<(ObjectRecord,&[u8]),Error>)
    requires forall|n:u64,p:&[u8]| #[trigger] hash.requires((format.magic,n,p)),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures ({
        let Format {magic,version,limit,scheme} = format;
        let at = loc.offset as int - base;
        let bytes = data@.subrange(at,at+52+loc.payload_len);
        let body = bytes.skip(52);
        &&& (out matches Err(Error::Bounds)) == !fits(data@,base,loc)
        &&& match out {
            Ok((r,p)) => p@ == body && loc.payload_len <= limit && bytes.take(8)==magic@ &&
                bytes.subrange(8,10)==seq![version as u8,(version >> 8) as u8] && bytes[10]==0 && bytes[11]==0 &&
                loc.payload_len==span::declared(bytes) && bytes.subrange(20,52)==loc.checksum@ &&
                hash.ensures((magic,loc.payload_len,p),loc.checksum) && record::tag(body,0,scheme) &&
                id.digest()==body.subrange(8,40) && record::record_at(body,40,scheme,r) &&
                exists|d:[u8;32]| d@==id.digest() && #[trigger] identify.ensures((&r,),d),
            Err(Error::Envelope(e)) => envelope(bytes,magic,version,loc,limit,hash,e),
            Err(Error::Record(record::Error::Decode(record::DecodeError::Tag(_)))) => !record::tag(body,0,scheme),
            Err(Error::Record(record::Error::Decode(record::DecodeError::Record(e)))) => !record::leaf_body(body,40) &&
                (record::complete_body(body,40,scheme) ==> e is Allocation),
            Err(Error::Record(record::Error::Identifier)) => id.digest()!=body.subrange(8,40),
            Err(Error::Record(record::Error::Identity)) => exists|r:ObjectRecord,d:[u8;32]| d@!=id.digest() &&
                record::record_at(body,40,scheme,r) && #[trigger] identify.ensures((&r,),d),
            Err(Error::Bounds)=>true,
        }
    }),
{
    let bytes = span::frame(data,base,loc.offset,loc.payload_len).ok_or(Error::Bounds)?;
    let p = match span::payload(bytes,format.magic,format.version,loc.payload_len,loc.checksum,format.limit,hash) {
        Ok(p)=>p,Err(e)=>return Err(Error::Envelope(e)),
    };
    match record::confirmed(p,format.scheme,id,identify) {
        Ok(r)=>Ok((r,p)),Err(e)=>Err(Error::Record(e)),
    }
}
}
