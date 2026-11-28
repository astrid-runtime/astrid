//! Restore an index from a complete or durably repaired cache region.
use crate::{ObjectId,checkpoint_admission as admission,root_wire::Scheme};
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {
/// Bytes covered by the history must be exactly the traversed physical prefix.
#[verifier::opaque]
pub(super) open spec fn decoded_cache<E,B:Fn(&admission::IndexState,u64)->Result<(),E>,G:Fn([u8;8],u64,&[u8])->[u8;32]>(
    image:Seq<u8>,end:u64,limit:u64,scheme:Scheme,validate:B,hash:G,s:admission::IndexState) -> bool {
    exists|calls:Seq<crate::frame_scan::Call>,states:Seq<admission::IndexState>|
        calls.len()>0 && states.last()==s &&
        #[trigger] crate::checkpoint_history::chain(calls,states,scheme,validate) &&
        crate::frame_scan::traversed(calls,0,end as int,image,crate::arena_frame::INDEX_MAGIC,crate::arena_frame::FRAME_VERSION,limit,hash)
}

pub(super) struct CacheImage<V> { pub(super) state:admission::IndexState,pub(super) end:u64,pub(super) fence:Option<V> }

pub(super) open spec fn persisted<V:crate::frontier::JournalContainer>(fence:Option<V>,target:(int,Seq<u8>),bytes:Seq<u8>,end:u64,original:u64) -> bool {
    match fence {
        None=>end==original,
        Some(v)=>end<original && (v.container_id(),v.region_id())==target && v.durable_image()==bytes,
    }
}

struct Scanned { state:Option<admission::IndexState>,tail:Option<(u64,crate::frame_repair::TailError)> }

/// A semantic refusal never turns into tail repair, even after a valid snapshot.
#[verifier::spinoff_prover]
fn scan<R:crate::frame_repair::FrameReader,E,B,G>(reader:&mut R,end:u64,limit:u64,scheme:Scheme,validate:B,hash:G)
    -> (out:Option<Scanned>)
    where B:Fn(&admission::IndexState,u64)->Result<(),E>+Copy,G:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(reader).position()==0,end==old(reader).image().len(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|s:&admission::IndexState,at:u64| #[trigger] validate.requires((s,at)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::INDEX_MAGIC,n,b)),
    ensures final(reader).target()==old(reader).target(),final(reader).image()==old(reader).image(),
        out matches Some(c) ==> {
            let at=match c.tail {None=>end,Some((at,_))=>at};
            &&& c.state matches Some(s) ==> 0<at && btree_map_inv(&s.objects) && decoded_cache(old(reader).image(),at,limit,scheme,validate,hash,s)
            &&& c.tail matches Some((a,e)) ==> a<end && (e is HeaderShort ==> end<a as int+52) &&
                crate::frame_scan::frame_failure(final(reader),a,end,crate::arena_frame::INDEX_MAGIC,crate::arena_frame::FRAME_VERSION,limit,hash,crate::frame_repair::FrameError::Tail(e))
        },
{
    use crate::{checkpoint_history::History,frame_scan,frame_scan::Stop,frame_repair::{self,FrameError},arena_frame::{INDEX_MAGIC,FRAME_VERSION}};
    let mut history=History::new(scheme,validate);
    let result=frame_scan::scan_index(reader,&mut history,end,limit,hash);
    let ghost calls=history.trace();
    assert(calls.skip(0) =~= calls);
    let tail=match result {
        Ok(())=>None,
        Err(Stop::Frame(at,FrameError::Tail(e)))=>{
            proof {if e is HeaderShort {
                let r=choose|r:R| r.target()==reader.target() && r.image()==reader.image() && r.position()==at &&
                    #[trigger] frame_repair::classified(&r,reader,at,end,INDEX_MAGIC,FRAME_VERSION,limit,hash,Err(FrameError::Tail(e)));
                assert(end<at as int+52);
            }}
            Some((at,e))
        }
        _=>return None,
    };
    let state=history.finish();
    proof {if let Some(s)=&state {
        let at=match tail {None=>end,Some((at,_))=>at};
        let states=choose|states:Seq<admission::IndexState>| #[trigger] crate::checkpoint_history::chain(calls,states,scheme,validate) && states.last()==*s;
        assert(crate::checkpoint_history::chain(calls,states,scheme,validate));
        assert(frame_scan::traversed(calls,0,at as int,reader.image(),INDEX_MAGIC,FRAME_VERSION,limit,hash));
        assert(calls.len()>0);
        assert(frame_scan::boundary(calls,calls.len(),0)>0);
        assert(decoded_cache(reader.image(),at,limit,scheme,validate,hash,*s)) by {reveal(decoded_cache);}
    }}
    Some(Scanned{state,tail})
}

#[verifier::spinoff_prover]
pub(super) fn recover_cache<R:crate::frame_repair::FrameReader,M:crate::frame_repair::Medium,E,B,G,V,O>(
    reader:&mut R,media:&mut M,end:u64,limit:u64,scheme:Scheme,validate:B,hash:G,capture:O)
    -> (out:Option<CacheImage<V>>)
    where B:Fn(&admission::IndexState,u64)->Result<(),E>+Copy,G:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        V:crate::frontier::JournalContainer,O:FnOnce(&M)->V,
    requires old(reader).target()==old(media).target(),old(reader).image()==old(media).bytes(),old(reader).position()==0,
        !old(media).syncs_file(),old(media).bytes()==old(media).durable(),end==old(reader).image().len(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|s:&admission::IndexState,at:u64| #[trigger] validate.requires((s,at)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::INDEX_MAGIC,n,b)),
        forall|m:&M| m.target()==old(media).target() ==> #[trigger] capture.requires((m,)),
        forall|m:&M,v:V| #[trigger] capture.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
    ensures final(reader).target()==old(reader).target(),final(reader).image()==old(reader).image(),
        out matches Some(c) ==> {
        &&& btree_map_inv(&c.state.objects) && 0<c.end<=end && final(media).target()==old(reader).target()
        &&& final(media).bytes()==old(reader).image().take(c.end as int)
        &&& persisted(c.fence,final(media).target(),final(media).bytes(),c.end,end)
        &&& (c.fence.is_none() ==> *final(media)==*old(media) && final(media).durable()==final(media).bytes())
        &&& decoded_cache(old(reader).image(),c.end,limit,scheme,validate,hash,c.state)
        &&& (c.end<end ==> !crate::frame_repair::has_later::<M>(old(reader).image(),c.end,end,crate::arena_frame::INDEX_MAGIC,limit))
    },
{
    use crate::{frame_repair::{self,Outcome},arena_frame::INDEX_MAGIC};
    let scanned=scan(reader,end,limit,scheme,validate,hash)?;
    let (at,fence)=match scanned.tail {
        None=>{assert(media.bytes().take(end as int) =~= media.bytes());(end,None)}
        Some((at,e))=>{
            match frame_repair::repair(media,at,end,0,e.damage(),INDEX_MAGIC,limit) {
                Ok(Outcome::Repaired)=>{},
                _=>return None,
            }
            proof {if e is HeaderShort {
                assert forall|next:u64| at<next implies !(#[trigger] crate::frame_probe::protects::<M>(old(reader).image(),INDEX_MAGIC,end,limit,next)) by {};
            }}
            let f=crate::hosted_journal_scan::persist_staged(media,capture).ok()?;
            (at,Some(f))
        }
    };
    let state=scanned.state?;
    Some(CacheImage{state,end:at,fence})
}

}
