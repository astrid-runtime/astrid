//! Resolve a principal's header from a validated journal and its recovered arena records.
use crate::{RootState, hosted_journal_history::{media_record,preload_closure}};
use std::collections::BTreeMap;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv,prelude::*};

verus! {
proof fn owning_row(refs:Seq<crate::ObjectReference>,i:int,id:crate::ObjectId)
    requires 0<=i<refs.len(),refs[i].fields().1==id,refs[i].fields().2==crate::ReferenceKind::Owns,
    ensures crate::closure_walk::children(refs).contains(id),
    decreases i,
{
    if i>0 {
        assert(refs.skip(1)[i-1]==refs[i]);
        owning_row(refs.skip(1),i-1,id);
    }
}

// Read the owner's graph from the immutable arena image used to rebuild the journal roots.
fn recovered_header<P:Ord,M:crate::positional_read::Media,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&crate::ObjectRecord)->[u8;32]+Copy>(
    index:&BTreeMap<crate::ObjectId,crate::ArenaLocation>,history:&BTreeMap<P,(RootState,u64)>,media:&M,target:u64,format:crate::indexed_frame::Format,hash:H,identify:I,candidate:BTreeMap<P,RootState>,owner:&P,v:crate::ObjectFormatVersion) -> (out:Option<(RootState,crate::header_graph::Graph,Option<crate::ObjectId>)>)
    requires btree_map_inv(&candidate),btree_map_inv(index),btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
    ensures out matches Some((root,g,head)) ==> {
        &&& history@.contains_key(*owner) && root==history@[*owner].0
        &&& index@.contains_key(root.commit) && index@.contains_key(g.state_id)
        &&& exists|r:crate::ObjectRecord| #[trigger] media_record(media.image(),(root.commit,index@[root.commit]),format.scheme,r)
            && g.commit.same_contents(&r)
        &&& exists|r:crate::ObjectRecord| #[trigger] media_record(media.image(),(g.state_id,index@[g.state_id]),format.scheme,r)
            && g.state.same_contents(&r)
        &&& crate::header_graph::state_edge(*g.commit) matches Some(edge) &&
            edge.fields()==(b"state"@,g.state_id,crate::ReferenceKind::Owns)
        &&& match head {
            None=>crate::header_graph::kv_edge(*g.state).is_none(),
            Some(id)=>crate::header_graph::kv_edge(*g.state) matches Some(edge) &&
                edge.fields()==(b"kv"@,id,crate::ReferenceKind::Owns) && index@.contains_key(id) &&
                exists|r:crate::ObjectRecord| #[trigger] media_record(media.image(),(id,index@[id]),format.scheme,r),
        }
    },
{
    let (roots,(table,_known))=preload_closure(index,history,media,target,format,hash,identify,candidate)?;
    let root=crate::root_transition::published(&roots,owner)?;
    let records=&table;
    let load=|_:&P,id:crate::ObjectId| -> (r:Result<std::sync::Arc<crate::ObjectRecord>,()>)
        ensures match r {Ok(rec)=>records@.contains_key(id) && rec.same_contents(&records@[id]),Err(())=>!records@.contains_key(id)},
    {
        match records.get(&id) {Some(r)=>Ok(std::sync::Arc::new(r.owned_record())),None=>Err(())}
    };
    let (g,head)=match crate::header_graph::read_kv(owner,root,v,load) {Ok(pair)=>pair,Err(_)=>return None};
    assert(media_record(media.image(),(root.commit,index@[root.commit]),format.scheme,table@[root.commit]));
    assert(media_record(media.image(),(g.state_id,index@[g.state_id]),format.scheme,table@[g.state_id]));
    proof {
        if let Some(id)=head {
            let refs=g.state.contents().3;
            let edge=choose|r:crate::ObjectReference| refs.contains(r) && r.fields()==(b"kv"@,id,crate::ReferenceKind::Owns);
            let i=choose|i:int| 0<=i<refs.len() && refs[i]==edge;
            let actual=table@[g.state_id].contents().3;
            assert(actual[i].fields()==edge.fields());
            owning_row(actual,i,id);
            assert(crate::journal_preload::outgoing(table@,g.state_id).subset_of(table@.dom()));
            assert(media_record(media.image(),(id,index@[id]),format.scheme,table@[id]));
        }
    }
    Some((root,g,head))
}
}
