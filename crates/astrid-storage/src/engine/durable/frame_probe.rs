//! Search the measured suffix for candidate frames before permitting truncation.
use vstd::prelude::*;

verus! {
pub(super) trait HashState {
    spec fn domain(&self) -> [u8;8];
    spec fn declared(&self) -> u64;
    spec fn input(&self) -> Seq<u8>;
    spec fn digest(domain:[u8;8],declared:u64,input:Seq<u8>) -> [u8;32];
    fn absorb(&mut self,bytes:&[u8])
        ensures final(self).domain()==old(self).domain(),final(self).declared()==old(self).declared(),
            final(self).input()==old(self).input()+bytes@;
    fn finish(self) -> (sum:[u8;32])
        ensures sum==Self::digest(self.domain(),self.declared(),self.input());
}

pub(super) trait Media {
    type Error;
    type Hasher:HashState;
    spec fn target(&self) -> (int,Seq<u8>);
    spec fn bytes(&self) -> Seq<u8>;
    spec fn calls(&self) -> Seq<super::frame_repair::Event>;
    spec fn durable(&self) -> Seq<u8>;
    spec fn syncs_file(&self) -> bool;
    spec fn cursor(&self) -> int;
    fn prepare_hash(magic:[u8;8],length:u64) -> (result:Result<(Self::Hasher,Vec<u8>),Self::Error>)
        ensures result matches Ok((h,buf)) ==> h.domain()==magic && h.declared()==length &&
            h.input()==Seq::<u8>::empty() && 0<buf.len()<=u64::MAX;
    fn read_window(&mut self,at:u64,buf:&mut [u8]) -> (out:Result<(),Self::Error>)
        requires at as int+old(buf).len()<=old(self).bytes().len(),
        ensures final(self).target()==old(self).target(),final(self).calls()==old(self).calls(),final(self).durable()==old(self).durable(),final(self).syncs_file()==old(self).syncs_file(),final(self).bytes()==old(self).bytes(),
            final(buf).len()==old(buf).len(),
            out.is_ok() ==> final(buf)@==old(self).bytes().subrange(at as int,at as int+old(buf).len());
    fn header(&mut self,at:u64) -> (out:Result<[u8;52],Self::Error>)
        requires at as int+52<=old(self).bytes().len(),
        ensures final(self).target()==old(self).target(),final(self).calls()==old(self).calls(),final(self).durable()==old(self).durable(),final(self).syncs_file()==old(self).syncs_file(),final(self).bytes()==old(self).bytes(),
            out matches Ok(h) ==> h@==old(self).bytes().subrange(at as int,at as int+52) && final(self).cursor()==at as int+52;
    fn read_chunk(&mut self,buf:&mut [u8]) -> (out:Result<(),Self::Error>)
        requires 0<=old(self).cursor()<=old(self).cursor()+old(buf).len()<=old(self).bytes().len(),
        ensures final(self).target()==old(self).target(),final(self).calls()==old(self).calls(),final(self).durable()==old(self).durable(),final(self).syncs_file()==old(self).syncs_file(),final(self).bytes()==old(self).bytes(),
            final(buf).len()==old(buf).len(), out.is_ok() ==> final(self).cursor()==old(self).cursor()+old(buf).len() &&
                final(buf)@==old(self).bytes().subrange(old(self).cursor(),final(self).cursor());
}

pub(super) open spec fn read_only<M:Media+?Sized>(before:&M,after:&M) -> bool {
    after.calls()==before.calls() && after.durable()==before.durable() && after.syncs_file()==before.syncs_file()
}

pub(super) enum Error<E> { Overflow, Io(E) }

/// Feed exactly the declared physical payload, in order, to the initialized hash.
fn checksum<M:Media>(media:&mut M,magic:[u8;8],length:u64) -> (out:Result<[u8;32],Error<M::Error>>)
    requires 0<=old(media).cursor()<=old(media).cursor()+length<=old(media).bytes().len(),
    ensures read_only(old(media),final(media)),final(media).target()==old(media).target(),final(media).bytes()==old(media).bytes(),
        out matches Ok(sum) ==> sum==M::Hasher::digest(magic,length,old(media).bytes().subrange(old(media).cursor(),old(media).cursor()+length)),
{
    let (mut hash,mut buffer)=match M::prepare_hash(magic,length) {Ok(pair)=>pair,Err(e)=>return Err(Error::Io(e))};
    let buffer=buffer.as_mut_slice();
    let mut left=length;
    while left>0
        invariant left<=length,0<buffer.len()<=u64::MAX,read_only(old(media),media),media.target()==old(media).target(),media.bytes()==old(media).bytes(),
            0<=old(media).cursor()<=media.cursor()==old(media).cursor()+length-left,old(media).cursor()+length<=media.bytes().len(),
            hash.domain()==magic,hash.declared()==length,hash.input()==media.bytes().subrange(old(media).cursor(),media.cursor()),
        decreases left,
    {
        let Ok(count)=usize::try_from(left.min(buffer.len() as u64)) else {return Err(Error::Overflow)};
        let part=&mut buffer[..count];
        let ghost from=media.cursor();
        assert(0<count<=left);
        assert(part.len()==count);
        assert(0<=from && from+count<=media.bytes().len());
        if let Err(e)=media.read_chunk(part) {return Err(Error::Io(e));}
        assert(media.cursor()==from+count);
        assert(part@==media.bytes().subrange(from,media.cursor()));
        hash.absorb(part);
        assert(media.bytes().subrange(old(media).cursor(),media.cursor()) =~= media.bytes().subrange(old(media).cursor(),from)+part@);
        left=left.saturating_sub(count as u64);
    }
    Ok(hash.finish())
}

/// A complete oversize envelope is a conservative barrier even without hashing
/// its payload. Bounded candidates must also carry the observed checksum.
pub(super) open spec fn protects<M:Media>(image:Seq<u8>,magic:[u8;8],end:u64,limit:u64,at:u64) -> bool {
    let pos=at as int;
    let h=image.subrange(pos,pos+52);
    let n=vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20));
    let version=super::arena_frame::FRAME_VERSION;
    &&& pos+52<=end && h.take(8)==magic@ && h[8]==version as u8 && h[9]==(version>>8) as u8
    &&& h[10]==0 && h[11]==0 && pos+52+n<=end
    &&& n>limit || M::Hasher::digest(magic,n,image.subrange(pos+52,pos+52+n))@==h.subrange(20,52)
}

pub(super) fn candidate<M:Media>(media:&mut M,at:u64,end:u64,magic:[u8;8],limit:u64) -> (out:Result<bool,Error<M::Error>>)
    requires at<=end<=old(media).bytes().len(),
    ensures final(media).target()==old(media).target(),read_only(old(media),final(media)),final(media).bytes()==old(media).bytes(),
        out matches Ok(v) ==> v==protects::<M>(old(media).bytes(),magic,end,limit,at),
{
    let remaining=end.saturating_sub(at);
    if remaining<52 {return Ok(false);}
    let h=match media.header(at) {Ok(h)=>h,Err(e)=>return Err(Error::Io(e))};
    if !super::arena_frame::magic_matches(&h,magic) {return Ok(false);}
    let Ok(decoded)=super::arena_frame::decode_header(&h,super::arena_frame::FRAME_VERSION) else {return Ok(false)};
    let n=decoded.payload_len;
    let Some(length)=52u64.checked_add(n) else {return Err(Error::Overflow)};
    if length>remaining {return Ok(false);}
    if n>limit {return Ok(true);}
    let sum=checksum(media,magic,n)?;
    let matches=sum.as_slice()==decoded.checksum.as_slice();
    if matches {assert(sum@ =~= decoded.checksum@);}
    assert(matches==protects::<M>(old(media).bytes(),magic,end,limit,at));
    Ok(matches)
}

/// A false result excludes every candidate start, including starts whose magic
/// spans the end of a window. Read or validation errors abort the search.
pub(super) fn search<M:Media>(media:&mut M,start:u64,end:u64,magic:[u8;8],limit:u64,buf:&mut [u8]) -> (out:Result<bool,Error<M::Error>>)
    requires end<=old(media).bytes().len(),8<=old(buf).len()<=u64::MAX,
    ensures final(media).target()==old(media).target(),read_only(old(media),final(media)),final(media).bytes()==old(media).bytes(),
        out matches Ok(v) ==> v==(exists|at:u64| start<=at && #[trigger] protects::<M>(old(media).bytes(),magic,end,limit,at)),
{
    let mut offset=start;
    while offset<end
        invariant start<=offset,8<=buf.len()==old(buf).len()<=u64::MAX,media.target()==old(media).target(),read_only(old(media),media),
            media.bytes()==old(media).bytes(),end<=media.bytes().len(),
            forall|at:u64| start<=at<offset ==> !(#[trigger] protects::<M>(media.bytes(),magic,end,limit,at)),
        decreases end as int-offset,
    {
        let remaining=end.saturating_sub(offset);
        let Ok(count)=usize::try_from(remaining.min(buf.len() as u64)) else {return Err(Error::Overflow)};
        let window=&mut buf[..count];
        if let Err(e)=media.read_window(offset,window) {return Err(Error::Io(e));}
        let mut i=0usize;
        while count.saturating_sub(i)>=8
            invariant start<=offset,i<=count,offset as int+count<=end<=media.bytes().len(),count==window.len(),
                window@==media.bytes().subrange(offset as int,offset as int+count),
                media.bytes()==old(media).bytes(),media.target()==old(media).target(),read_only(old(media),media),
                forall|at:u64| start<=at<offset as int+i ==> !(#[trigger] protects::<M>(media.bytes(),magic,end,limit,at)),
            decreases count-i,
        {
            let at=offset.saturating_add(i as u64);
            let bytes=&window[i..i.saturating_add(8)];
            assert(bytes@ =~= media.bytes().subrange(at as int,at as int+8));
            if bytes==magic.as_slice() && candidate(media,at,end,magic,limit)? {
                assert(protects::<M>(media.bytes(),magic,end,limit,at));
                assert(protects::<M>(old(media).bytes(),magic,end,limit,at));
                return Ok(true);
            }
            proof {if at as int+52<=end {assert(media.bytes().subrange(at as int,at as int+52).take(8) =~= bytes@);}}
            assert(!protects::<M>(media.bytes(),magic,end,limit,at));
            i=i.saturating_add(1);
        }
        if remaining<=count as u64 {
            return Ok(false);
        }
        // The next window begins at the first unexamined candidate start.
        offset=offset.saturating_add(i as u64);
    }
    Ok(false)
}
}
