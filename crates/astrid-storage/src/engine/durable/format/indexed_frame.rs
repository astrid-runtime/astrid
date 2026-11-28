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
