//! Classify a damaged journal suffix and sequence repair on the same media handle.
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Bound { Live(u64), Committed {start:u64,end:u64} }

#[derive(Clone,Copy)]
pub(super) struct Window {
    pub(super) start:u64, pub(super) end:u64, pub(super) protected:u64, pub(super) restore_cursor:bool,
}

pub(super) fn window(physical:u64,bound:Bound) -> (out:Option<Window>)
    ensures match bound {
        Bound::Live(p) => out.is_some() == (p <= physical) && (out matches Some(w) ==>
            w.start == 0 && w.end == physical && w.protected == p && !w.restore_cursor),
        Bound::Committed {start,end} => out.is_some() == (start <= end <= physical) && (out matches Some(w) ==>
            w.start == start && w.end == end && w.protected == end && w.restore_cursor),
    },
{
    match bound {
        Bound::Live(p) if p <= physical => Some(Window {start:0,end:physical,protected:p,restore_cursor:false}),
        Bound::Committed {start,end} if start <= end && end <= physical =>
            Some(Window {start,end,protected:end,restore_cursor:true}),
        _ => None,
    }
}

pub(super) enum Extent { Complete(u64), Incomplete, Oversize {interior:bool}, Overflow }

pub(super) fn extent(offset:u64,end:u64,len:u64,limit:u64) -> (out:Extent)
    ensures ({
        let next = offset as int + super::arena_frame::WIDTH + len;
        match out {
            Extent::Complete(n) => len <= limit && n == next && offset < n <= end,
            Extent::Incomplete => len <= limit && end < next <= u64::MAX,
            Extent::Overflow => len <= limit && next > u64::MAX,
            Extent::Oversize {interior} => len > limit && interior == (next <= end),
        }
    }),
{
    let next = match (super::arena_frame::WIDTH as u64).checked_add(len) {Some(n) => offset.checked_add(n),None => None};
    if len > limit {return Extent::Oversize {interior:match next {Some(n) => n <= end,None => false}};}
    match next {
        None => Extent::Overflow,
        Some(n) if n > end => Extent::Incomplete,
        Some(n) => Extent::Complete(n),
    }
}

/// The logical cursor excludes read-ahead held by the underlying buffered reader.
pub(super) trait FrameReader {
    type Error;
    spec fn image(&self) -> Seq<u8>;
    spec fn position(&self) -> int;
    spec fn target(&self) -> (int,Seq<u8>);
    spec fn failed(&self,at:int,size:u64,e:Self::Error) -> bool;
    fn header(&mut self) -> (out:Result<[u8;52],Self::Error>)
        ensures final(self).image()==old(self).image(),final(self).target()==old(self).target(),
            out matches Ok(bytes) ==> final(self).position()==old(self).position()+52 &&
                bytes@==old(self).image().subrange(old(self).position(),final(self).position()),
            out matches Err(e) ==> old(self).failed(old(self).position(),52,e);
    fn payload(&mut self,size:u64) -> (out:Result<Vec<u8>,Self::Error>)
        ensures final(self).image()==old(self).image(),final(self).target()==old(self).target(),
            out matches Ok(bytes) ==> bytes.len()==size && final(self).position()==old(self).position()+size &&
                bytes@==old(self).image().subrange(old(self).position(),final(self).position()),
            out matches Err(e) ==> old(self).failed(old(self).position(),size,e);
}

/// Pass the bytes read for this header to the scanner only after its checksum agrees.
pub(super) fn read_payload<R:FrameReader,H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    reader:&mut R,header:super::arena_frame::DecodedFrameHeader,magic:[u8;8],hash:H)
    -> (out:Result<Option<Vec<u8>>,R::Error>)
    requires forall|b:&[u8]| #[trigger] hash.requires((magic,header.payload_len,b)),
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        out.is_ok() ==> final(reader).position()==old(reader).position()+header.payload_len,
        out matches Err(e) ==> old(reader).failed(old(reader).position(),header.payload_len,e),
        out matches Ok(Some(bytes)) ==> bytes.len()==header.payload_len &&
            bytes@==old(reader).image().subrange(old(reader).position(),final(reader).position()) &&
            (exists|b:&[u8]| b@==bytes@ && #[trigger] hash.ensures((magic,header.payload_len,b),header.checksum)),
        out matches Ok(None) ==> exists|b:&[u8],sum:[u8;32]| b@==old(reader).image().subrange(old(reader).position(),final(reader).position()) &&
            b.len()==header.payload_len && sum!=header.checksum && #[trigger] hash.ensures((magic,header.payload_len,b),sum),
{
    let bytes=reader.payload(header.payload_len)?;
    let b=bytes.as_slice();
    match super::arena_frame::check_payload(header,magic,b,hash) {
        Ok(_)=>Ok(Some(bytes)),
        Err(_)=>Ok(None),
    }
}

pub(super) enum FrameError<E> {
    Io(E), Header(super::arena_frame::HeaderError), Overflow, Tail(TailError),
}

pub(super) enum TailError {
    HeaderShort, Magic, Oversize {size:u64,interior:bool}, PayloadShort, Checksum,
}

pub(super) struct ScannedFrame { pub(super) end:u64,pub(super) body:Vec<u8> }

pub(super) open spec fn header_at(image:Seq<u8>,offset:u64) -> Seq<u8> {
    image.subrange(offset as int,offset as int+52)
}

/// Read one frame at the logical cursor. Tail repair and callback errors are
/// handled by the caller; only an authenticated complete frame can be emitted.
#[verifier::spinoff_prover]
pub(super) fn next_frame<R:FrameReader,H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    reader:&mut R,offset:u64,end:u64,magic:[u8;8],version:u16,limit:u64,hash:H)
    -> (out:Result<ScannedFrame,FrameError<R::Error>>)
    requires old(reader).position()==offset,offset<end<=old(reader).image().len(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
    ensures final(reader).target()==old(reader).target(),final(reader).image()==old(reader).image(),{
        let at=offset as int;
        if end<at+52 {
            out matches Err(FrameError::Tail(TailError::HeaderShort))
        } else {
            let image=old(reader).image();let h=header_at(image,offset);
            let n=vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20));
            let next=at+52+n;
            let matches=h.take(8)==magic@;
            let current=h[8]==version as u8 && h[9]==(version >> 8) as u8;
            let clear=h[10]==0 && h[11]==0;
            let valid=matches && current && clear;
            match out {
                Ok(f)=>valid && n<=limit && at<f.end==next<=end &&
                    super::arena_frame::WIDTH==52 && final(reader).position()==f.end &&
                    f.body.len()==n && f.body@==image.subrange(at+52,next) &&
                    exists|b:&[u8],sum:[u8;32]| b@==f.body@ && sum@==h.subrange(20,52) && #[trigger] hash.ensures((magic,n,b),sum),
                Err(FrameError::Tail(TailError::HeaderShort))=>false,
                Err(FrameError::Tail(TailError::Magic))=>!matches,
                Err(FrameError::Header(super::arena_frame::HeaderError::Version))=>matches && !current,
                Err(FrameError::Header(super::arena_frame::HeaderError::Reserved))=>matches && current && !clear,
                Err(FrameError::Tail(TailError::Oversize{size,interior}))=>valid && size==n && n>limit && interior==(next<=end),
                Err(FrameError::Overflow)=>valid && n<=limit && next>u64::MAX,
                Err(FrameError::Tail(TailError::PayloadShort))=>valid && n<=limit && end<next<=u64::MAX,
                Err(FrameError::Tail(TailError::Checksum))=>valid && n<=limit && next<=end &&
                    exists|b:&[u8],sum:[u8;32]| b@==image.subrange(at+52,next) &&
                        sum@!=h.subrange(20,52) && #[trigger] hash.ensures((magic,n,b),sum),
                Err(FrameError::Io(e))=>old(reader).failed(at,52,e) || valid && n<=limit && next<=end &&
                    exists|r:R| r.image()==image && r.target()==old(reader).target() && r.position()==at+52 && #[trigger] r.failed(at+52,n,e),
            }
        }
    },
{
    use super::arena_frame as frame;
    if end.saturating_sub(offset)<super::arena_frame::WIDTH as u64 {return Err(FrameError::Tail(TailError::HeaderShort));}
    let h=match reader.header() {Ok(h)=>h,Err(e)=>return Err(FrameError::Io(e))};
    if !frame::magic_matches(&h,magic) {return Err(FrameError::Tail(TailError::Magic));}
    let decoded=match frame::decode_header(&h,version) {Ok(d)=>d,Err(e)=>return Err(FrameError::Header(e))};
    let next=match extent(offset,end,decoded.payload_len,limit) {
        Extent::Complete(n)=>n,Extent::Incomplete=>return Err(FrameError::Tail(TailError::PayloadShort)),
        Extent::Overflow=>return Err(FrameError::Overflow),
        Extent::Oversize{interior}=>return Err(FrameError::Tail(TailError::Oversize{size:decoded.payload_len,interior})),
    };
    let ghost cursor=*reader;
    match read_payload(reader,decoded,magic,hash) {
        Ok(Some(body))=>{
            proof {
                let b=choose|b:&[u8]| b@==body@ && #[trigger] hash.ensures((magic,decoded.payload_len,b),decoded.checksum);
                assert(frame::hashed(hash,magic,body@,decoded.checksum));
            }
            Ok(ScannedFrame{end:next,body})
        },
        Ok(None)=>{
            proof {
                let bytes=cursor.image().subrange(cursor.position(),reader.position());
                let (p,sum)=choose|p:&[u8],sum:[u8;32]| p@==bytes && p.len()==decoded.payload_len &&
                    sum!=decoded.checksum && #[trigger] hash.ensures((magic,decoded.payload_len,p),sum);
                if sum@==decoded.checksum@ {assert(sum =~= decoded.checksum);}
                assert(sum@!=decoded.checksum@);
            }
            Err(FrameError::Tail(TailError::Checksum))
        },
        Err(e)=>{assert(cursor.failed(offset as int+52,decoded.payload_len,e));Err(FrameError::Io(e))}
    }
}

#[derive(Clone,Copy)]
pub(super) enum Damage { Incomplete, Suspect { known_interior:bool } }

#[cfg(verus_keep_ghost)]
pub(super) enum Event { Probe(u64), Resize(u64), Flush }

pub(super) trait Medium {
    type Error;
    spec fn calls(&self) -> Seq<Event>;
    spec fn bytes(&self) -> Seq<u8>;
    spec fn durable(&self) -> Seq<u8>;
    spec fn probe_result(&self, offset:u64, result:Result<bool,Self::Error>) -> bool;

    fn later_frame(&mut self,offset:u64) -> (out:Result<bool,Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Probe(offset)),
            final(self).bytes() == old(self).bytes(), final(self).durable() == old(self).durable(),
            old(self).probe_result(offset,out);

    fn resize(&mut self,offset:u64) -> (out:Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Resize(offset)),
            out.is_ok() && offset <= old(self).bytes().len() ==> final(self).bytes() == old(self).bytes().take(offset as int);

    fn flush(&mut self) -> (out:Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Flush),
            out.is_ok() ==> final(self).durable() == old(self).bytes() && final(self).bytes() == old(self).bytes();
}

pub(super) enum Outcome { Reject, Repaired }
pub(super) enum Error<E> { Probe(E), Resize(E), Flush(E) }

pub(super) fn repair<M:Medium>(media:&mut M,offset:u64,end:u64,protected:u64,damage:Damage)
    -> (out:Result<Outcome,Error<M::Error>>)
    ensures ({
        let before = old(media).calls();
        let blocked = offset < protected || offset >= end || (damage matches Damage::Suspect {known_interior:true});
        let probe = !blocked && (damage matches Damage::Suspect {known_interior:false});
        let prefix = if probe {before.push(Event::Probe(offset))} else {before};
        &&& match out {
            Ok(Outcome::Reject) => (blocked || (probe && old(media).probe_result(offset,Ok(true)))) &&
                final(media).calls() == prefix && final(media).bytes() == old(media).bytes() &&
                final(media).durable() == old(media).durable(),
            Err(Error::Probe(e)) => probe && old(media).probe_result(offset,Err(e)) &&
                final(media).calls() == prefix && final(media).bytes() == old(media).bytes() &&
                final(media).durable() == old(media).durable(),
            _ => !blocked && (probe ==> old(media).probe_result(offset,Ok(false))) &&
                match out {
                    Err(Error::Resize(_)) => final(media).calls() == prefix.push(Event::Resize(offset)),
                    _ => final(media).calls() == prefix.push(Event::Resize(offset)).push(Event::Flush),
                },
        }
        &&& out matches Ok(Outcome::Repaired) ==> (offset <= old(media).bytes().len() ==>
            final(media).bytes() == old(media).bytes().take(offset as int) && final(media).durable() == final(media).bytes())
    }),
{
    if offset < protected || offset >= end {return Ok(Outcome::Reject);}
    if let Damage::Suspect {known_interior} = damage {
        if known_interior {return Ok(Outcome::Reject);}
        match media.later_frame(offset) {
            Ok(false) => {},
            Ok(true) => return Ok(Outcome::Reject),
            Err(e) => return Err(Error::Probe(e)),
        }
    }
    if let Err(e) = media.resize(offset) {return Err(Error::Resize(e));}
    if let Err(e) = media.flush() {return Err(Error::Flush(e));}
    Ok(Outcome::Repaired)
}
}
