//! Bind KV writer edges and marker identity to the commit selected by root CAS.
use crate::{header_graph,header_writer,root_declaration,root_transition,transaction_records,
    ObjectFormatVersion,ObjectId,ObjectRecord,ObjectReference,ReferenceKind,RootState};
use std::collections::BTreeMap;
use vstd::{prelude::*,std_specs::btree::btree_map_inv,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},laws_eq::obeys_concrete_eq};

verus! {

pub(crate) struct Graph<P> {
    pub(crate) selected:root_transition::SelectedRoot<P>,
    pub(crate) component:ObjectId,
    pub(crate) state:ObjectId,
    pub(crate) records:BTreeMap<ObjectId,ObjectRecord>,
}

pub(crate) enum Error { State, Commit, Collision(ObjectId), Selection(root_transition::SelectionError) }

impl<P> Graph<P> {
    pub(crate) open spec fn links(&self,owner:P,prior:Option<RootState>,record:ObjectRecord,v:ObjectFormatVersion) -> bool {
        let bound=self.selected.binding();
        let rows=self.records@;
        &&& bound.0==owner && bound.1==prior
        &&& rows.dom()==set![self.component,self.state,bound.2.commit]
        &&& rows[self.component]==record
        &&& header_graph::structural(rows[self.state],crate::ObjectKind::PrincipalState,v)
        &&& header_graph::structural(rows[bound.2.commit],crate::ObjectKind::Commit,v)
        &&& header_graph::state_edge(rows[bound.2.commit]) matches Some(e) && e.fields()==(header_graph::STATE@,self.state,ReferenceKind::Owns)
        &&& header_graph::kv_edge(rows[self.state]) matches Some(e) && e.fields()==(header_graph::KV@,self.component,ReferenceKind::Owns)
        &&& match prior {None=>bound.2.generation.value()==0,Some(p)=>bound.2.generation.value() as int==p.generation.value() as int+1}
    }
}

/// Build the actual component, state and commit declarations before selecting the
/// replacement generation. Other retained references may point to existing objects.
pub(crate) fn prepare<P:Ord,I:Fn(&ObjectRecord)->ObjectId+Copy>(
    owner:P,prior:Option<RootState>,component:ObjectRecord,state_refs:Vec<ObjectReference>,commit_refs:Vec<ObjectReference>,
    v:ObjectFormatVersion,identify:I,pending:&BTreeMap<P,RootState>,published:&BTreeMap<P,RootState>)
    -> (out:Result<Graph<P>,Error>)
    requires obeys_cmp::<ObjectReference>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        obeys_concrete_eq::<ObjectRecord>(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        btree_map_inv(pending),btree_map_inv(published),forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures out matches Ok(g) ==> g.links(owner,prior,component,v) && btree_map_inv(&g.records) &&
        (if pending@.contains_key(owner) {Some(pending@[owner])} else {published@.get(owner)})==prior &&
        forall|id:ObjectId| g.records@.contains_key(id) ==> #[trigger] identify.ensures((&g.records@[id],),id),
        out matches Err(Error::Selection(root_transition::SelectionError::Conflict{expected,actual})) ==> expected==prior &&
            actual!=expected && actual==(if pending@.contains_key(owner) {Some(pending@[owner])} else {published@.get(owner)}),
{
    let head=transaction_records::identify(component,identify);
    let state=match header_writer::kv_state(state_refs,head.0,v) {Some(r)=>transaction_records::identify(r,identify),None=>return Err(Error::State)};
    let commit=match header_writer::commit(commit_refs,prior,state.0,v) {Some(r)=>transaction_records::identify(r,identify),None=>return Err(Error::Commit)};
    let id=head.0;
    let state_id=state.0;
    let commit_id=commit.0;
    let update=root_declaration::Update{principal:owner,expected:prior,commit:commit_id,records:vec![head,state,commit]};
    let (selected,rows)=match root_transition::select_update(pending,published,update) {Ok(v)=>v,Err(e)=>return Err(Error::Selection(e))};
    let table=match transaction_records::unique(rows) {Ok(t)=>t,Err(k)=>return Err(Error::Collision(k))};
    proof {
        assert(table@.contains_key(id) && table@[id]==head.1);
        assert(table@.contains_key(state_id) && table@[state_id]==state.1);
        assert(table@.contains_key(commit_id) && table@[commit_id]==commit.1);
        assert forall|k:ObjectId| #[trigger] table@.contains_key(k) implies k==id || k==state_id || k==commit_id by {
            let j=choose|j:int| 0<=j<rows.len() && #[trigger] rows@[j].0==k;
            if j==0 {} else if j==1 {} else {assert(j==2);}
        }
        assert(table@.dom() =~= set![id,state_id,commit_id]);
    }
    Ok(Graph{selected,component:id,state:state_id,records:table})
}
}
