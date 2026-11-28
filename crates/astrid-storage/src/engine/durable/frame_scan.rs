//! Traverse a measured interval and offer each authenticated frame to its consumer.
use super::frame_repair::{self, FrameError, FrameReader};
use vstd::prelude::*;

verus! {
#[cfg(verus_keep_ghost)]
pub(super) type Call=(u64,Seq<u8>);

pub(super) trait Visitor<R:FrameReader> {
    type Error;
    spec fn ready(&self) -> bool;
    spec fn calls(&self) -> Seq<Call>;
    #[cfg(verus_keep_ghost)]
    type Config;
    spec fn config(&self) -> Self::Config;
    spec fn refused(&self,prior:&Self,bytes:Seq<u8>,error:Self::Error) -> bool;
    fn visit(&mut self,reader:&mut R,at:u64,bytes:&[u8]) -> (result:Result<(),Self::Error>)
        requires old(self).ready(),
        ensures result.is_ok() ==> final(self).ready(),final(self).calls()==old(self).calls().push((at,bytes@)),
            final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
            result.is_ok() ==> final(reader).position()==old(reader).position(),
            final(self).config()==old(self).config(),
            result matches Err(e) ==> final(self).refused(old(self),bytes@,e);
}

pub(super) enum Stop<F,V> { Frame(u64,FrameError<F>), Visitor(u64,Vec<u8>,V) }

pub(super) open spec fn boundary(calls:Seq<Call>,n:nat,start:u64) -> int {
    if n==0 {start as int} else {let (offset,body)=calls[n-1];offset as int+52+body.len()}
}

pub(super) open spec fn authentic<H:Fn([u8;8],u64,&[u8])->[u8;32]>(image:Seq<u8>,at:u64,body:Seq<u8>,magic:[u8;8],version:u16,limit:u64,hash:H) -> bool {
    let next=at as int+52+body.len();
    &&& next<=image.len() && body.len()<=limit
    &&& exists|b:&[u8],sum:[u8;32]| b@==body && #[trigger] hash.ensures((magic,body.len() as u64,b),sum) &&
        image.subrange(at as int,next)==super::arena_frame::header_bytes(magic,version,body.len() as u64,sum)+body
}

pub(super) open spec fn traversed<H:Fn([u8;8],u64,&[u8])->[u8;32]>(calls:Seq<Call>,start:u64,end:int,image:Seq<u8>,magic:[u8;8],version:u16,limit:u64,hash:H) -> bool {
    &&& boundary(calls,calls.len(),start)==end
    &&& forall|i:int| 0<=i<calls.len() ==> (#[trigger] calls[i]).0==boundary(calls,i as nat,start) &&
        authentic(image,calls[i].0,calls[i].1,magic,version,limit,hash)
}

pub(super) open spec fn frame_failure<R:FrameReader,H:Fn([u8;8],u64,&[u8])->[u8;32]>(after:&R,at:u64,end:u64,magic:[u8;8],version:u16,limit:u64,hash:H,e:FrameError<R::Error>) -> bool {
    exists|r:R| r.target()==after.target() && r.image()==after.image() && r.position()==at &&
        #[trigger] frame_repair::classified(&r,after,at,end,magic,version,limit,hash,Err(e))
}

pub(super) open spec fn rejected<R:FrameReader,V:Visitor<R>>(v:&V,calls:Seq<Call>,e:V::Error) -> bool {
    exists|prior:V| prior.ready() && prior.config()==v.config() && prior.calls()==calls.drop_last() &&
        #[trigger] v.refused(&prior,calls.last().1,e)
}

#[derive(Clone,Copy)]
pub(super) struct Window {
    pub(super) start:u64, pub(super) end:u64, pub(super) magic:[u8;8], pub(super) version:u16, pub(super) limit:u64,
}

pub(super) open spec fn scanned<R:FrameReader,V:Visitor<R>,H:Fn([u8;8],u64,&[u8])->[u8;32]>(before:&R,reader:&R,prior:&V,visitor:&V,
    window:Window,hash:H,out:Result<(),Stop<R::Error,V::Error>>) -> bool {
    visitor.config()==prior.config() && reader.target()==before.target() && reader.image()==before.image() && {
        let calls=visitor.calls().skip(prior.calls().len() as int);
        &&& visitor.calls()==prior.calls()+calls
        &&& match out {
            Ok(())=>visitor.ready() && traversed(calls,window.start,window.end as int,before.image(),window.magic,window.version,window.limit,hash) && reader.position()==window.end,
            Err(Stop::Frame(at,e))=>visitor.ready() && at<window.end && traversed(calls,window.start,at as int,before.image(),window.magic,window.version,window.limit,hash) &&
                frame_failure(reader,at,window.end,window.magic,window.version,window.limit,hash,e),
            Err(Stop::Visitor(at,body,e))=>at==calls.last().0 && body@==calls.last().1 && rejected::<R,V>(visitor,visitor.calls(),e) && calls.len()>0 && boundary(calls,calls.len(),window.start)<=window.end &&
                traversed(calls,window.start,boundary(calls,calls.len(),window.start),before.image(),window.magic,window.version,window.limit,hash),
        }
    }
}

/// The live native root journal and its proof enter the same scan at zero.
pub(super) fn scan_root<R:FrameReader,V:Visitor<R>,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(reader:&mut R,visitor:&mut V,
    end:u64,limit:u64,hash:H) -> (out:Result<(),Stop<R::Error,V::Error>>)
    requires old(visitor).ready(),end<=old(reader).image().len(),old(reader).position()==0,
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((super::arena_frame::ROOT_MAGIC,n,b)),
    ensures scanned(old(reader),final(reader),old(visitor),final(visitor),
        Window{start:0,end,magic:super::arena_frame::ROOT_MAGIC,version:super::arena_frame::FRAME_VERSION,limit},hash,out),
{
    let window=Window{start:0,end,magic:super::arena_frame::ROOT_MAGIC,version:super::arena_frame::FRAME_VERSION,limit};
    scan(reader,visitor,window,hash)
}

proof fn authenticated_frame<R:FrameReader,H:Fn([u8;8],u64,&[u8])->[u8;32]>(before:&R,after:&R,offset:u64,end:u64,
    magic:[u8;8],version:u16,limit:u64,hash:H,f:frame_repair::ScannedFrame)
    requires end<=before.image().len(), frame_repair::classified(before,after,offset,end,magic,version,limit,hash,Ok(f)),
    ensures authentic(before.image(),offset,f.body@,magic,version,limit,hash),
{
            let image=before.image();let at=offset as int;
            let h=frame_repair::header_at(image,offset);
            let n=vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20));
            let (b,sum)=choose|b:&[u8],sum:[u8;32]| b@==f.body@ && sum@==h.subrange(20,52) && #[trigger] hash.ensures((magic,n,b),sum);
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(h.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(n));
            assert(h =~= super::arena_frame::header_bytes(magic,version,n,sum));
            assert(image.subrange(at,f.end as int) =~= h+f.body@);
            assert(authentic(image,offset,f.body@,magic,version,limit,hash));
        }

#[verifier::rlimit(25)]
#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
pub(super) fn scan<R:FrameReader,V:Visitor<R>,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(reader:&mut R,visitor:&mut V,
    window:Window,hash:H) -> (out:Result<(),Stop<R::Error,V::Error>>)
    requires old(visitor).ready(),window.start<=window.end<=old(reader).image().len(),old(reader).position()==window.start,
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((window.magic,n,b)),
    ensures scanned(old(reader),final(reader),old(visitor),final(visitor),window,hash,out),

{
    let start=window.start;let end=window.end;let magic=window.magic;let version=window.version;let limit=window.limit;
    let mut offset=start;
    let ghost mut calls:Seq<Call>=Seq::empty();
    while offset<end
        invariant visitor.config()==old(visitor).config(),visitor.ready(),start<=offset<=end,reader.position()==offset,reader.target()==old(reader).target(),reader.image()==old(reader).image(),
            visitor.calls()==old(visitor).calls()+calls,traversed(calls,start,offset as int,reader.image(),magic,version,limit,hash),
        decreases end-offset,
    {
        let ghost cursor=*reader;
        let f=match frame_repair::next_frame(reader,offset,end,magic,version,limit,hash) {
            Ok(f)=>f,Err(e)=>{
                assert(visitor.calls().skip(old(visitor).calls().len() as int) =~= calls);
                assert(frame_repair::classified(&cursor,reader,offset,end,magic,version,limit,hash,Err(e)));
                assert(frame_failure(reader,offset,end,magic,version,limit,hash,e));
                return Err(Stop::Frame(offset,e))
            }
        };
        proof {authenticated_frame(&cursor,reader,offset,end,magic,version,limit,hash,f);}
        let ghost prior=*visitor;
        let accepted=visitor.visit(reader,offset,&f.body);
        proof {
            let prior=calls;
            calls=calls.push((offset,f.body@));
            assert(visitor.calls() =~= old(visitor).calls()+calls);
            assert forall|i:int| 0<=i<calls.len() implies (#[trigger] calls[i]).0==boundary(calls,i as nat,start) &&
                authentic(reader.image(),calls[i].0,calls[i].1,magic,version,limit,hash) by {
                if i<prior.len() {assert(calls[i]==prior[i]);}
                if i>0 {assert(calls[i-1]==prior[i-1]);}
            }
            assert(traversed(calls,start,f.end as int,reader.image(),magic,version,limit,hash));
        }
        if let Err(e)=accepted {
            assert(visitor.calls().skip(old(visitor).calls().len() as int) =~= calls);
            assert(prior.calls() =~= visitor.calls().drop_last());
            assert(visitor.refused(&prior,visitor.calls().last().1,e));
            assert(rejected::<R,V>(visitor,visitor.calls(),e));
            return Err(Stop::Visitor(offset,f.body,e))
        }
        offset=f.end;
    }
    assert(visitor.calls().skip(old(visitor).calls().len() as int) =~= calls);
    Ok(())
}
}
