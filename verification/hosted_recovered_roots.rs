//! Join the actual recovered journal history to the physical retained arena.
use crate::{ArenaLocation,ObjectId,ObjectRecord,RootState,arena_frame,frame_repair,hosted_journal_scan as journal,
    hosted_journal_history as preload,indexed_frame::Format,journal_closure,positional_read,root_wire};
use std::collections::{BTreeMap,BTreeSet};
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {
pub(crate) struct Loaded<P> {
    pub(crate) roots:BTreeMap<P,RootState>,
    pub(crate) records:BTreeMap<ObjectId,ObjectRecord>,
    pub(crate) known:BTreeSet<ObjectId>,
    pub(crate) history:Ghost<Map<P,(RootState,u64)>>,
    pub(crate) end:u64,
}

pub(crate) open spec fn retained<P:Ord>(v:&Loaded<P>,image:Seq<u8>,index:Map<ObjectId,ArenaLocation>,scheme:root_wire::Scheme) -> bool {
    let h=v.history@;
    &&& v.roots@.dom()==h.dom()
    &&& forall|p:P| #[trigger] h.contains_key(p) ==> v.roots@[p]==h[p].0
    &&& v.known@==v.records@.dom() && v.known@.subset_of(index.dom())
    &&& crate::journal_preload::closed_on(v.records@,v.known@)
    &&& preload::backed_by_arena(image,index,scheme,v.records@)
    &&& forall|p:P| #[trigger] h.contains_key(p) ==> exists|s:Set<ObjectId>| #[trigger] journal_closure::admitted(&v.records,h[p].0.commit,s) && s.subset_of(v.known@)
    &&& forall|k:ObjectId| #[trigger] v.known@.contains(k) ==> exists|p:P,s:Set<ObjectId>| h.contains_key(p) && #[trigger] journal_closure::admitted(&v.records,h[p].0.commit,s) && s.contains(k)
}

/// Reopen a native journal and read the closure of precisely its recovered
/// roots from a distinct arena. Even an arbitrary index must pass the reads,
/// record checks, graph validation and checked root projection.
pub(crate) fn recover_indexed<R:frame_repair::FrameReader,M:frame_repair::Medium,A:positional_read::Media,
    P:Ord,D,C,H,I,F>(reader:&mut R,media:&mut M,arena:&A,index:&BTreeMap<ObjectId,ArenaLocation>,end:u64,
    protected:u64,batch:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H,identify:I,project:F)
    -> (out:Option<Loaded<P>>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        I:Fn(&ObjectRecord)->[u8;32]+Copy,F:FnOnce(&BTreeMap<P,(RootState,u64)>)->BTreeMap<P,RootState>,
    requires old(reader).target()==old(media).target(),arena.target()!=old(reader).target(),
        old(reader).image()==old(media).bytes(),old(media).syncs_file(),old(media).durable()==old(media).bytes(),
        old(reader).position()==0,protected<=end==old(reader).image().len(),btree_map_inv(index),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|h:&BTreeMap<P,(RootState,u64)>| #[trigger] project.requires((h,)),
        forall|h:&BTreeMap<P,(RootState,u64)>,t:BTreeMap<P,RootState>| #[trigger] project.ensures((h,),t) ==> btree_map_inv(&t),
    ensures out matches Some(v) ==> final(media).target()==old(reader).target() && arena.target()!=final(media).target() &&
        protected<=v.end<=end && final(media).durable()==old(reader).image().take(v.end as int) &&
        journal::recovered(v.history@,final(media).durable(),v.end,limit,scheme,decode,recode,hash) &&
        retained(&v,arena.image(),index@,scheme),
{
    let (at,history)=match journal::recover_live(reader,media,end,protected,limit,scheme,decode,recode,hash) {
        journal::Live::Complete(t)=>{assert(media.durable().take(end as int) =~= media.durable());(end,t)},
        journal::Live::Repaired(at,_,t)=>(at,t),
        _=>return None,
    };
    let candidate=project(&history);
    let format=Format{magic:arena_frame::ARENA_MAGIC,version:arena_frame::FRAME_VERSION,scheme,limit};
    let (roots,(records,known))=preload::preload_closure(index,&history,arena,batch,format,hash,identify,candidate)?;
    assert(format.scheme==scheme);
    assert(preload::backed_by_arena(arena.image(),index@,format.scheme,records@));
    let v=Loaded{roots,records,known,history:Ghost(history@),end:at};
    proof {
        let h=v.history@;
        assert(v.roots@.dom()==h.dom());
        assert(forall|p:P| #[trigger] h.contains_key(p) ==> v.roots@[p]==h[p].0);
        assert(v.known@==v.records@.dom() && v.known@.subset_of(index@.dom()));
        assert(crate::journal_preload::closed_on(v.records@,v.known@));
        assert(preload::backed_by_arena(arena.image(),index@,scheme,v.records@));
        assert(forall|p:P| #[trigger] h.contains_key(p) ==> exists|s:Set<ObjectId>| #[trigger] journal_closure::admitted(&v.records,h[p].0.commit,s) && s.subset_of(v.known@));
        assert(forall|k:ObjectId| #[trigger] v.known@.contains(k) ==> exists|p:P,s:Set<ObjectId>| h.contains_key(p) && #[trigger] journal_closure::admitted(&v.records,h[p].0.commit,s) && s.contains(k));
    }
    assert(retained(&v,arena.image(),index@,scheme));
    Some(v)
}
}
