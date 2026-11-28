//! Recover the actual arena index from an arbitrary measured image.
use crate::{ArenaLocation,ObjectId,ObjectRecord,arena_frame::{ARENA_MAGIC,FRAME_VERSION},
    arena_history::{self,History},frame_repair::{self,FrameError,FrameReader,Medium,Outcome},
    frame_scan::{self,Call,Stop,Visitor},recovered_record::IndexError,root_wire::Scheme};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {
type Index=(BTreeMap<ObjectId,ArenaLocation>,Option<ArenaLocation>);
pub(crate) enum Recovery<E,F> {
    Loaded(u64,Index),Frame(u64,FrameError<E>),Record(u64,Vec<u8>,IndexError),Media(u64,frame_repair::TailError,frame_repair::Error<F>),
}

pub(crate) open spec fn indexed<I,C,H>(map:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,
    image:Seq<u8>,end:u64,limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H) -> bool
    where I:Fn(&ObjectRecord)->ObjectId,C:Fn(u64,&[u8])->[u8;32],H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    exists|calls:Seq<Call>| #[trigger] frame_scan::traversed(calls,0,end as int,image,ARENA_MAGIC,FRAME_VERSION,limit,hash) &&
        arena_history::folded(calls,map,tail,scheme,identify,checksum)
}

/// Any selected entry names an authenticated frame in the recovered physical prefix.
proof fn locate<I,C,H>(map:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,key:ObjectId,
    image:Seq<u8>,end:u64,limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H)
    where I:Fn(&ObjectRecord)->ObjectId,C:Fn(u64,&[u8])->[u8;32],H:Fn([u8;8],u64,&[u8])->[u8;32],
    requires indexed(map,tail,image,end,limit,scheme,identify,checksum,hash),map.contains_key(key),
    ensures exists|body:Seq<u8>| #[trigger] frame_scan::authentic(image,map[key].offset,body,ARENA_MAGIC,FRAME_VERSION,limit,hash) &&
        arena_history::placement((map[key].offset,body),key,map[key],scheme,identify,checksum),
{
    let calls=choose|calls:Seq<Call>| #[trigger] frame_scan::traversed(calls,0,end as int,image,ARENA_MAGIC,FRAME_VERSION,limit,hash) &&
        arena_history::folded(calls,map,tail,scheme,identify,checksum);
    arena_history::locate(calls,map,tail,key,scheme,identify,checksum);
    let j=choose|j:int| 0<=j<calls.len() && #[trigger] arena_history::placement(calls[j],key,map[key],scheme,identify,checksum);
    assert(frame_scan::authentic(image,calls[j].0,calls[j].1,ARENA_MAGIC,FRAME_VERSION,limit,hash));
}

pub(crate) open spec fn record_refused<I,C,H>(calls:Seq<Call>,map:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,image:Seq<u8>,
    end:u64,limit:u64,at:u64,body:Seq<u8>,scheme:Scheme,identify:I,checksum:C,hash:H,e:IndexError) -> bool
    where I:Fn(&ObjectRecord)->ObjectId,C:Fn(u64,&[u8])->[u8;32],H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    let next=frame_scan::boundary(calls,calls.len(),0);
    &&& calls.len()>0 && next<=end && calls.last()==(at,body)
    &&& frame_scan::traversed(calls,0,next,image,ARENA_MAGIC,FRAME_VERSION,limit,hash)
    &&& arena_history::folded(calls.drop_last(),map,tail,scheme,identify,checksum)
    &&& arena_history::refusal(map,body,scheme,identify,checksum,e)
}

pub(crate) closed spec fn record_failure<I,C,H>(image:Seq<u8>,end:u64,limit:u64,at:u64,body:Seq<u8>,scheme:Scheme,identify:I,checksum:C,hash:H,e:IndexError) -> bool
    where I:Fn(&ObjectRecord)->ObjectId,C:Fn(u64,&[u8])->[u8;32],H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    exists|calls,map,tail| #[trigger] record_refused(calls,map,tail,image,end,limit,at,body,scheme,identify,checksum,hash,e)
}

pub(crate) fn recover<R:FrameReader,M:Medium,I,C,H>(reader:&mut R,media:&mut M,end:u64,protected:u64,
    limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H) -> (out:Recovery<R::Error,M::Error>)
    where I:Fn(&ObjectRecord)->ObjectId+Copy,C:Fn(u64,&[u8])->[u8;32]+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(reader).target()==old(media).target(),old(reader).image()==old(media).bytes(),old(reader).position()==0,
        old(media).durable()==old(media).bytes(),protected<=end==old(reader).image().len(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|n:u64,b:&[u8]| #[trigger] checksum.requires((n,b)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ARENA_MAGIC,n,b)),
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),final(media).target()==old(media).target(),
        match out {
            Recovery::Loaded(at,(map,tail))=>btree_map_inv(&map) && protected<=at<=end &&
                final(media).bytes()==old(reader).image().take(at as int) && (at==end ==> *final(media)==*old(media)) &&
                ((at==end || old(media).syncs_file()) ==> final(media).durable()==final(media).bytes()) &&
                indexed(map@,tail,old(reader).image(),at,limit,scheme,identify,checksum,hash) &&
                (at<end ==> !frame_repair::has_later::<M>(old(reader).image(),at,end,ARENA_MAGIC,limit)),
            Recovery::Record(at,b,e)=>*final(media)==*old(media) && frame_scan::authentic(old(reader).image(),at,b@,ARENA_MAGIC,FRAME_VERSION,limit,hash) &&
                record_failure(old(reader).image(),end,limit,at,b@,scheme,identify,checksum,hash,e),
            Recovery::Frame(at,e)=>at<end && final(media).durable()==old(media).durable() && frame_scan::frame_failure(final(reader),at,end,ARENA_MAGIC,FRAME_VERSION,limit,hash,e),
            Recovery::Media(at,e,f)=>protected<=at<end &&
                frame_scan::frame_failure(final(reader),at,end,ARENA_MAGIC,FRAME_VERSION,limit,hash,FrameError::Tail(e)) &&
                (f is Probe ==> final(media).bytes()==old(media).bytes() && final(media).durable()==old(media).durable()),
        },
        end==0 ==> (out matches Recovery::Loaded(at,(map,tail)) && at==0 && map@==Map::<ObjectId,ArenaLocation>::empty() && tail.is_none() && *final(media)==*old(media)),
{
    let mut visitor=History::new(scheme,identify,checksum);
    let outcome=frame_scan::scan_arena(reader,&mut visitor,end,limit,hash);
    let ghost calls=visitor.trace();
    assert(calls.skip(0) =~= calls);
    let at=match outcome {
        Ok(())=>{assert(media.bytes().take(end as int) =~= media.bytes());end}
        Err(Stop::Visitor(at,b,e))=>{
            assert(calls[calls.len()-1]==(at,b@));
            proof {
                let p=choose|p:History<I,C>| p.valid() && p.settings()==(scheme,identify,checksum) && p.trace()==calls.drop_last() &&
                    #[trigger] <History<I,C> as Visitor<R>>::refused(&visitor,&p,calls.last().1,e);
                p.certificate();
                assert(record_refused(calls,p.state().0,p.state().1,reader.image(),end,limit,at,b@,scheme,identify,checksum,hash,e));
            }
            assert(frame_scan::authentic(old(reader).image(),at,b@,ARENA_MAGIC,FRAME_VERSION,limit,hash));
            assert(record_failure(old(reader).image(),end,limit,at,b@,scheme,identify,checksum,hash,e));
            assert(*media==*old(media));
            assert(end>0);
            return Recovery::Record(at,b,e);
        }
        Err(Stop::Frame(at,FrameError::Tail(e)))=>{
            match frame_repair::repair(media,at,end,protected,e.damage(),ARENA_MAGIC,limit) {
                Ok(Outcome::Reject)=>return Recovery::Frame(at,FrameError::Tail(e)),
                Err(f)=>return Recovery::Media(at,e,f),
                Ok(Outcome::Repaired)=>{
                    proof {
                        if e is HeaderShort {
                            let r=choose|r:R| r.target()==reader.target() && r.image()==reader.image() && r.position()==at &&
                                #[trigger] frame_repair::classified(&r,reader,at,end,ARENA_MAGIC,FRAME_VERSION,limit,hash,Err(FrameError::Tail(e)));
                            assert(end<at as int+52);
                            assert forall|next:u64| at<next implies !(#[trigger] crate::frame_probe::protects::<M>(r.image(),ARENA_MAGIC,end,limit,next)) by {};
                        }
                    }
                    at
                }
            }
        }
        Err(Stop::Frame(at,e))=>return Recovery::Frame(at,e),
    };
    let (map,tail)=visitor.finish();
    assert(frame_scan::traversed(calls,0,at as int,reader.image(),ARENA_MAGIC,FRAME_VERSION,limit,hash));
    assert(arena_history::folded(calls,map@,tail,scheme,identify,checksum));
    proof {
        if end==0 {
            if calls.len()>0 {assert(frame_scan::boundary(calls,calls.len(),0)>0);}
            assert(calls =~= Seq::<Call>::empty());
            arena_history::empty(map@,tail,scheme,identify,checksum);
        }
    }
    Recovery::Loaded(at,(map,tail))
}
enum VolumeIndex<E,F,V:crate::frontier::JournalContainer> {
    Clean(Index),Persisted(u64,Index,V),Frame(u64,FrameError<E>),Record(u64,Vec<u8>,IndexError),
    Media(u64,frame_repair::TailError,frame_repair::Error<F>),Container(u64,V::Error),
}

/// The volume fence follows a real resize and precedes release of the index.
fn recover_volume<R:FrameReader,M:Medium,I,C,H,V:crate::frontier::JournalContainer,F:FnOnce(&M)->V>(
    reader:&mut R,media:&mut M,end:u64,protected:u64,limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H,capture:F)
    -> (out:VolumeIndex<R::Error,M::Error,V>)
    where I:Fn(&ObjectRecord)->ObjectId+Copy,C:Fn(u64,&[u8])->[u8;32]+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires !old(media).syncs_file(),old(reader).target()==old(media).target(),old(reader).image()==old(media).bytes(),old(reader).position()==0,
        old(media).durable()==old(media).bytes(),protected<=end==old(reader).image().len(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),forall|n:u64,b:&[u8]| #[trigger] checksum.requires((n,b)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ARENA_MAGIC,n,b)),
        forall|m:&M| m.target()==old(media).target() ==> #[trigger] capture.requires((m,)),
        forall|m:&M,v:V| #[trigger] capture.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
    ensures final(media).target()==old(media).target(),
        out matches VolumeIndex::Clean((map,tail)) ==> *final(media)==*old(media) && btree_map_inv(&map) &&
            indexed(map@,tail,old(reader).image(),end,limit,scheme,identify,checksum,hash),
        out matches VolumeIndex::Persisted(at,(map,tail),v) ==> protected<=at<end && btree_map_inv(&map) && final(media).bytes()==v.durable_image() &&
            (v.container_id(),v.region_id())==old(reader).target() && v.durable_image()==old(reader).image().take(at as int) &&
            indexed(map@,tail,old(reader).image(),at,limit,scheme,identify,checksum,hash),
        out matches VolumeIndex::Container(at,e) ==> protected<=at<end && final(media).bytes()==old(reader).image().take(at as int) &&
            crate::hosted_journal_scan::container_failure::<V>(old(media).target(),old(reader).image().take(at as int),e),
{
    match recover(reader,media,end,protected,limit,scheme,identify,checksum,hash) {
        Recovery::Loaded(at,index)=>{
            if at==end {return VolumeIndex::Clean(index);}
            match crate::hosted_journal_scan::persist_staged(media,capture) {
                Ok(region)=>VolumeIndex::Persisted(at,index,region),
                Err(e)=>VolumeIndex::Container(at,e),
            }
        }
        Recovery::Frame(at,e)=>VolumeIndex::Frame(at,e),
        Recovery::Record(at,b,e)=>VolumeIndex::Record(at,b,e),
        Recovery::Media(at,e,f)=>VolumeIndex::Media(at,e,f),
    }
}

/// Reopen the positional handle after possible truncation and use the index
/// produced by scanning this very arena to restore the root journal.
struct Reopened<P> {
    loaded:crate::hosted_recovered_roots::Loaded<P>,
    arena_end:u64,
    index:Ghost<Map<ObjectId,ArenaLocation>>,
    tail:Ghost<Option<ArenaLocation>>,
}

#[verifier::spinoff_prover]
fn reopen<S:FrameReader,T:Medium,A:crate::positional_read::Media,R:FrameReader,M:Medium,P:Ord,I,C,H,D,E,F,O>(
    scan:&mut S,backing:&mut T,open:O,reader:&mut R,journal:&mut M,arena_end:u64,arena_protected:u64,
    end:u64,protected:u64,batch:u64,limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H,decode:D,recode:E,project:F)
    -> (out:Option<Reopened<P>>)
    where I:Fn(&ObjectRecord)->ObjectId+Copy,C:Fn(u64,&[u8])->[u8;32]+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        D:Fn(&[u8])->Option<P>+Copy,E:Fn(&P)->Vec<u8>+Copy,O:FnOnce(&T)->Option<A>,
        F:FnOnce(&BTreeMap<P,(crate::RootState,u64)>)->BTreeMap<P,crate::RootState>,
    requires old(scan).target()==old(backing).target(),old(scan).image()==old(backing).bytes(),old(scan).position()==0,
        old(backing).syncs_file(),old(backing).bytes()==old(backing).durable(),arena_protected<=arena_end==old(scan).image().len(),
        old(reader).target()==old(journal).target(),old(reader).image()==old(journal).bytes(),old(reader).position()==0,
        old(journal).syncs_file(),old(journal).bytes()==old(journal).durable(),protected<=end==old(reader).image().len(),
        old(scan).target()!=old(reader).target(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|m:&T| #[trigger] open.requires((m,)),
        forall|m:&T,a:A| #[trigger] open.ensures((m,),Some(a)) ==> a.target()==m.target() && a.image()==m.durable(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),forall|n:u64,b:&[u8]| #[trigger] checksum.requires((n,b)),
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
        forall|n:u64,b:&[u8],s:[u8;32]| #[trigger] checksum.ensures((n,b),s) ==> hash.ensures((ARENA_MAGIC,n,b),s),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>| #[trigger] project.requires((h,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>,t:BTreeMap<P,crate::RootState>| #[trigger] project.ensures((h,),t) ==> btree_map_inv(&t),
    ensures out matches Some(v) ==> {
        &&& final(backing).target()==old(scan).target() && final(journal).target()==old(reader).target()
        &&& arena_protected<=v.arena_end<=arena_end && protected<=v.loaded.end<=end
        &&& final(backing).durable()==old(scan).image().take(v.arena_end as int)
        &&& final(journal).durable()==old(reader).image().take(v.loaded.end as int)
        &&& indexed(v.index@,v.tail@,old(scan).image(),v.arena_end,limit,scheme,identify,checksum,hash)
        &&& crate::hosted_journal_scan::recovered(v.loaded.history@,final(journal).durable(),v.loaded.end,limit,scheme,decode,recode,hash)
        &&& crate::hosted_recovered_roots::retained(&v.loaded,final(backing).durable(),v.index@,scheme)
    },
{
    let (at,index,tail)=match recover(scan,backing,arena_end,arena_protected,limit,scheme,identify,checksum,hash) {
        Recovery::Loaded(at,(index,tail))=>(at,index,tail),
        _=>return None,
    };
    let arena=open(backing)?;
    let digest=|r:&ObjectRecord| -> (s:[u8;32]) ensures exists|id:ObjectId| #[trigger] identify.ensures((r,),id) && s@==id.digest(),
        {let id=identify(r);*id.as_bytes()};
    let loaded=crate::hosted_recovered_roots::recover_indexed(reader,journal,&arena,&index,end,protected,batch,limit,
        scheme,decode,recode,hash,digest,project)?;
    Some(Reopened{loaded,arena_end:at,index:Ghost(index@),tail:Ghost(tail)})
}

struct VolumeRoots<P,V,J> {
    state:Reopened<P>,
    arena_fence:Option<V>,
    root_fence:Option<J>,
}

spec fn stable_region<V:crate::frontier::JournalContainer>(fence:Option<V>,target:(int,Seq<u8>),image:Seq<u8>,end:u64) -> bool {
    match fence {
        None=>end==image.len(),
        Some(v)=>end<image.len() && (v.container_id(),v.region_id())==target && v.durable_image()==image.take(end as int),
    }
}

/// The two named regions share a volume. Keep both successful repair receipts
/// and read the selected objects through a positional handle after journal repair.
#[verifier::spinoff_prover]
fn reopen_volume<S:FrameReader,T:Medium,A:crate::positional_read::Media,R:FrameReader,M:Medium,P:Ord,I,C,H,D,E,F,O,
    V:crate::frontier::JournalContainer,J:crate::frontier::JournalContainer,AV:FnOnce(&T)->V,JV:FnOnce(&M)->J>(
    scan:&mut S,backing:&mut T,open:O,arena_region:AV,reader:&mut R,journal:&mut M,root_region:JV,arena_end:u64,arena_protected:u64,
    end:u64,protected:u64,batch:u64,limit:u64,scheme:Scheme,identify:I,checksum:C,hash:H,decode:D,recode:E,project:F)
    -> (out:Option<VolumeRoots<P,V,J>>)
    where I:Fn(&ObjectRecord)->ObjectId+Copy,C:Fn(u64,&[u8])->[u8;32]+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        D:Fn(&[u8])->Option<P>+Copy,E:Fn(&P)->Vec<u8>+Copy,O:FnOnce(&T)->Option<A>,
        F:FnOnce(&BTreeMap<P,(crate::RootState,u64)>)->BTreeMap<P,crate::RootState>,
    requires old(scan).target()==old(backing).target(),old(scan).image()==old(backing).bytes(),old(scan).position()==0,
        !old(backing).syncs_file(),old(backing).bytes()==old(backing).durable(),arena_protected<=arena_end==old(scan).image().len(),
        old(reader).target()==old(journal).target(),old(reader).image()==old(journal).bytes(),old(reader).position()==0,
        !old(journal).syncs_file(),old(journal).bytes()==old(journal).durable(),protected<=end==old(reader).image().len(),
        old(scan).target().0==old(reader).target().0,old(scan).target().1!=old(reader).target().1,
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|m:&T| m.target()==old(backing).target() ==> #[trigger] arena_region.requires((m,)),
        forall|m:&T,v:V| #[trigger] arena_region.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
        forall|m:&M| m.target()==old(journal).target() ==> #[trigger] root_region.requires((m,)),
        forall|m:&M,v:J| #[trigger] root_region.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
        forall|m:&T| #[trigger] open.requires((m,)),
        forall|m:&T,a:A| #[trigger] open.ensures((m,),Some(a)) ==> a.target()==m.target() && a.image()==m.bytes(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),forall|n:u64,b:&[u8]| #[trigger] checksum.requires((n,b)),
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
        forall|n:u64,b:&[u8],s:[u8;32]| #[trigger] checksum.ensures((n,b),s) ==> hash.ensures((ARENA_MAGIC,n,b),s),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>| #[trigger] project.requires((h,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>,t:BTreeMap<P,crate::RootState>| #[trigger] project.ensures((h,),t) ==> btree_map_inv(&t),
    ensures out matches Some(v) ==> {
        let r=v.state;
        &&& final(backing).target()==old(scan).target() && final(journal).target()==old(reader).target()
        &&& final(backing).target().0==final(journal).target().0 && final(backing).target().1!=final(journal).target().1
        &&& arena_protected<=r.arena_end<=arena_end && protected<=r.loaded.end<=end
        &&& (v.arena_fence.is_none() ==> final(backing).durable()==final(backing).bytes())
        &&& (v.root_fence.is_none() ==> final(journal).durable()==final(journal).bytes())
        &&& stable_region(v.arena_fence,final(backing).target(),old(scan).image(),r.arena_end)
        &&& stable_region(v.root_fence,final(journal).target(),old(reader).image(),r.loaded.end)
        &&& final(backing).bytes()==old(scan).image().take(r.arena_end as int) && final(journal).bytes()==old(reader).image().take(r.loaded.end as int)
        &&& indexed(r.index@,r.tail@,old(scan).image(),r.arena_end,limit,scheme,identify,checksum,hash)
        &&& crate::hosted_journal_scan::recovered(r.loaded.history@,final(journal).bytes(),r.loaded.end,limit,scheme,decode,recode,hash)
        &&& crate::hosted_recovered_roots::retained(&r.loaded,final(backing).bytes(),r.index@,scheme)
    },
{
    use crate::hosted_journal_scan::{self as roots,VolumeRecovery};
    let (ae,(index,tail),af)=match recover_volume(scan,backing,arena_end,arena_protected,limit,scheme,identify,checksum,hash,arena_region) {
        VolumeIndex::Clean(t)=>{assert(backing.bytes().take(arena_end as int) =~= backing.bytes());(arena_end,t,None)},
        VolumeIndex::Persisted(at,t,v)=>(at,t,Some(v)),
        _=>return None,
    };
    let (re,history,rf)=match roots::recover_volume(reader,journal,end,protected,limit,scheme,decode,recode,hash,root_region) {
        VolumeRecovery::Unmodified(t)=>{assert(journal.bytes().take(end as int) =~= journal.bytes());(end,t,None)},
        VolumeRecovery::Persisted(at,t,v)=>(at,t,Some(v)),
        _=>return None,
    };
    let arena=open(backing)?;
    let digest=|r:&ObjectRecord| -> (s:[u8;32]) ensures exists|id:ObjectId| #[trigger] identify.ensures((r,),id) && s@==id.digest(),
        {let id=identify(r);*id.as_bytes()};
    let loaded=crate::hosted_recovered_roots::load_history(history,re,&arena,&index,batch,limit,scheme,hash,digest,project)?;
    let state=Reopened{loaded,arena_end:ae,index:Ghost(index@),tail:Ghost(tail)};
    Some(VolumeRoots{state,arena_fence:af,root_fence:rf})
}

}
