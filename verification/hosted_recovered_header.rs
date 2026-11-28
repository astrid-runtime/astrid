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

pub(crate) struct RecoveredGraph<P> {
    pub(crate) owner:P,
    pub(crate) root:RootState,
    pub(crate) graph:crate::header_graph::Graph,
    pub(crate) component:Option<crate::ObjectId>,
    pub(crate) records:BTreeMap<crate::ObjectId,crate::ObjectRecord>,
}

pub(crate) open spec fn decoded_root<E,Check:Fn(&[u8])->Option<E>>(record:&crate::ObjectRecord,v:crate::ObjectFormatVersion,
    check:Check,result:Result<crate::delta_chain::Head,crate::projection_record::Error<E>>) -> bool {
    exists|label:&[u8]| label@==crate::projection_record::ROOT_LABEL@ &&
        #[trigger] crate::projection_record::valid(record,v,label,check,result)
}

impl<P> RecoveredGraph<P> {
    pub(crate) open spec fn from_arena(&self,image:Seq<u8>,index:Map<crate::ObjectId,crate::ArenaLocation>,scheme:crate::root_wire::Scheme,v:crate::ObjectFormatVersion) -> bool {
        let root=self.root;
        let g=self.graph;
        &&& btree_map_inv(&self.records)
        &&& self.records@.dom().subset_of(index.dom())
        &&& forall|id:crate::ObjectId| self.records@.contains_key(id) ==> #[trigger] media_record(image,(id,index[id]),scheme,self.records@[id])
        &&& crate::header_graph::structural(*g.commit,crate::ObjectKind::Commit,v)
        &&& crate::header_graph::structural(*g.state,crate::ObjectKind::PrincipalState,v)
        &&& index.contains_key(root.commit) && index.contains_key(g.state_id)
        &&& exists|r:crate::ObjectRecord| #[trigger] media_record(image,(root.commit,index[root.commit]),scheme,r)
            && g.commit.same_contents(&r)
        &&& exists|r:crate::ObjectRecord| #[trigger] media_record(image,(g.state_id,index[g.state_id]),scheme,r)
            && g.state.same_contents(&r)
        &&& crate::header_graph::state_edge(*g.commit) matches Some(edge) &&
            edge.fields()==(b"state"@,g.state_id,crate::ReferenceKind::Owns)
        &&& match self.component {
            None=>crate::header_graph::kv_edge(*g.state).is_none(),
            Some(id)=>crate::header_graph::kv_edge(*g.state) matches Some(edge) &&
                edge.fields()==(b"kv"@,id,crate::ReferenceKind::Owns) && index.contains_key(id) &&
                self.records@.contains_key(id) && media_record(image,(id,index[id]),scheme,self.records@[id]),
        }
    }
    /// Decode the namespace map selected by this recovered owner's state edge.
    pub(crate) fn decode_component<E,Check:Fn(&[u8])->Option<E>+Copy,Select:FnOnce(crate::ObjectId)->Check>(
        &self,v:crate::ObjectFormatVersion,select:Select)
        -> (out:Option<Result<crate::delta_chain::Head,crate::projection_record::Error<E>>>)
        requires btree_map_inv(&self.records),obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
            self.component matches Some(id) ==> self.records@.contains_key(id) && select.requires((id,)),
            forall|id:crate::ObjectId,check:Check,b:&[u8]| self.component==Some(id) && #[trigger] select.ensures((id,),check) ==> #[trigger] check.requires((b,)),
        ensures out.is_some()==self.component.is_some(),
            out matches Some(result) ==> self.component matches Some(id) &&
                exists|check:Check| select.ensures((id,),check) &&
                    #[trigger] decoded_root(&self.records@[id],v,check,result),
    {
        let id=self.component?;
        let record=self.records.get(&id).unwrap();
        let check=select(id);
        let label=crate::projection_record::ROOT_LABEL.as_slice();
        let result=crate::projection_record::decode(record,v,label,check);
        assert(crate::projection_record::valid(record,v,label,check,result));
        assert(label@==crate::projection_record::ROOT_LABEL@);
        assert(decoded_root(&self.records@[id],v,check,result));
        Some(result)
    }

}

// Read the owner's graph from the immutable arena image used to rebuild the journal roots.
pub(crate) fn recovered_header<P:Ord+Copy,M:crate::positional_read::Media,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&crate::ObjectRecord)->[u8;32]+Copy>(
    index:&BTreeMap<crate::ObjectId,crate::ArenaLocation>,history:&BTreeMap<P,(RootState,u64)>,media:&M,target:u64,format:crate::indexed_frame::Format,hash:H,identify:I,candidate:BTreeMap<P,RootState>,owner:&P,v:crate::ObjectFormatVersion) -> (out:Option<RecoveredGraph<P>>)
    requires btree_map_inv(&candidate),btree_map_inv(index),btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
    ensures out matches Some(graph) ==> graph.owner==*owner && history@.contains_key(*owner) && graph.root==history@[*owner].0 &&
        graph.from_arena(media.image(),index@,format.scheme,v),
{
    let (roots,(table,_known))=preload_closure(index,history,media,target,format,hash,identify,candidate)?;
    header_from_table(roots,table,owner,v,Ghost(media.image()),Ghost(index@),format.scheme)
}

/// Resolve the requesting owner directly from the table retained by cold restart.
pub(crate) fn loaded_header<P:Ord+Copy>(loaded:crate::hosted_recovered_roots::Loaded<P>,owner:&P,
    v:crate::ObjectFormatVersion,image:Ghost<Seq<u8>>,index:Ghost<Map<crate::ObjectId,crate::ArenaLocation>>,
    scheme:crate::root_wire::Scheme) -> (out:Option<RecoveredGraph<P>>)
    requires crate::hosted_recovered_roots::retained(&loaded,image@,index@,scheme),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
    ensures out matches Some(g) ==> g.owner==*owner && loaded.history@.contains_key(*owner) &&
        g.root==loaded.history@[*owner].0 && g.records@==loaded.records@ && g.from_arena(image@,index@,scheme,v),
{
    header_from_table(loaded.roots,loaded.records,owner,v,image,index,scheme)
}

fn header_from_table<P:Ord+Copy>(roots:BTreeMap<P,RootState>,table:BTreeMap<crate::ObjectId,crate::ObjectRecord>,
    owner:&P,v:crate::ObjectFormatVersion,image:Ghost<Seq<u8>>,index:Ghost<Map<crate::ObjectId,crate::ArenaLocation>>,
    scheme:crate::root_wire::Scheme) -> (out:Option<RecoveredGraph<P>>)
    requires btree_map_inv(&roots),btree_map_inv(&table),table@.dom().subset_of(index@.dom()),
        crate::journal_preload::closed_on(table@,table@.dom()),crate::hosted_journal_history::backed_by_arena(image@,index@,scheme,table@),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
    ensures out matches Some(g) ==> g.owner==*owner && roots@.contains_key(*owner) && g.root==roots@[*owner] &&
        g.records@==table@ && g.from_arena(image@,index@,scheme,v),
{
    let root=crate::root_transition::published(&roots,owner)?;
    let records=&table;
    let load=|_:&P,id:crate::ObjectId| -> (r:Result<std::sync::Arc<crate::ObjectRecord>,()>)
        ensures match r {Ok(rec)=>records@.contains_key(id) && rec.same_contents(&records@[id]),Err(())=>!records@.contains_key(id)},
    {
        match records.get(&id) {Some(r)=>Ok(std::sync::Arc::new(r.owned_record())),None=>Err(())}
    };
    let (g,head)=match crate::header_graph::read_kv(owner,root,v,load) {Ok(pair)=>pair,Err(_)=>return None};
    assert(media_record(image@,(root.commit,index@[root.commit]),scheme,table@[root.commit]));
    assert(media_record(image@,(g.state_id,index@[g.state_id]),scheme,table@[g.state_id]));
    proof {
        if let Some(id)=head {
            let refs=g.state.contents().3;
            let edge=choose|r:crate::ObjectReference| refs.contains(r) && r.fields()==(b"kv"@,id,crate::ReferenceKind::Owns);
            let i=choose|i:int| 0<=i<refs.len() && refs[i]==edge;
            let actual=table@[g.state_id].contents().3;
            assert(actual[i].fields()==edge.fields());
            owning_row(actual,i,id);
            assert(crate::journal_preload::outgoing(table@,g.state_id).subset_of(table@.dom()));
            assert(media_record(image@,(id,index@[id]),scheme,table@[id]));
        }
    }
    Some(RecoveredGraph{owner:*owner,root,graph:g,component:head,records:table})
}
}
