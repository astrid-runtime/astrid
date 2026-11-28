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
