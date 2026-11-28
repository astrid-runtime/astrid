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
    pub(crate) open spec fn retained(&self,state_refs:Seq<ObjectReference>,commit_refs:Seq<ObjectReference>) -> bool {
        let (_,prior,root)=self.selected.binding();
        let state=self.records@[self.state];
        let commit=self.records@[root.commit];
        let kv=header_graph::kv_edge(state).unwrap();
        let owned=header_graph::state_edge(commit).unwrap();
        &&& state.contents().3.to_multiset()==state_refs.to_multiset().insert(kv)
        &&& match prior {
            None=>commit.contents().3.to_multiset()==commit_refs.to_multiset().insert(owned),
            Some(old)=>exists|parent:ObjectReference| parent.fields()==(header_writer::PARENT@,old.commit,ReferenceKind::Lineage)
                && commit.contents().3.to_multiset()==commit_refs.to_multiset().insert(parent).insert(owned),
        }
    }

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
    ensures out matches Ok(g) ==> g.links(owner,prior,component,v) && g.retained(state_refs@,commit_refs@) && btree_map_inv(&g.records) &&
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

proof fn selected_member(refs:Seq<ObjectReference>,label:Seq<u8>,lo:int,hi:int,edge:ObjectReference)
    requires crate::reference_lookup::selected(refs,label,lo,hi)==Some(edge),
    ensures refs.contains(edge),
    decreases hi-lo,
{
    let mid=lo+(hi-lo)/2;
    if refs[mid].fields().0==label {assert(refs[mid]==edge);}
    else if ObjectRecord::label_before(refs[mid].fields().0,label) {selected_member(refs,label,mid+1,hi,edge);}
    else {selected_member(refs,label,lo,mid,edge);}
}

proof fn owning_child(refs:Seq<ObjectReference>,i:int)
    requires 0<=i<refs.len(),refs[i].fields().2 is Owns,
    ensures crate::closure_walk::children(refs).contains(refs[i].fields().1),
    decreases i,
{
    if i>0 {
        assert(refs.skip(1)[i-1]==refs[i]);
        owning_child(refs.skip(1),i-1);
    }
}

proof fn selected_child(record:ObjectRecord,label:Seq<u8>,id:ObjectId)
    requires crate::reference_lookup::selected(record.contents().3,label,0,record.contents().3.len() as int)
        matches Some(e) && e.fields()==(label,id,ReferenceKind::Owns),
    ensures crate::closure_walk::children(record.contents().3).contains(id),
{
    let refs=record.contents().3;
    let edge=crate::reference_lookup::selected(refs,label,0,refs.len() as int).unwrap();
    selected_member(refs,label,0,refs.len() as int,edge);
    owning_child(refs,choose|i:int| 0<=i<refs.len() && refs[i]==edge);
}

/// Run the recovery materializer on a preloaded table. Other retained references
/// can lead outside the declaration. A successful closure must include the
/// selected marker even when those references lead to additional records.
pub(crate) fn materialize<'a,P>(g:&Graph<P>,table:&'a BTreeMap<ObjectId,ObjectRecord>,v:ObjectFormatVersion)
    -> (out:Result<Vec<(ObjectId,&'a ObjectRecord)>,crate::closure_walk::Failure<ObjectId,ObjectId>>)
    requires g.links(g.selected.binding().0,g.selected.binding().1,g.records@[g.component],v),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),btree_map_inv(table),
        forall|id:ObjectId| #[trigger] g.records@.contains_key(id) ==> table@.contains_key(id) && table@[id]==g.records@[id],
    ensures out matches Ok(rows) ==> {
        let ids=crate::closure_load::row_ids(rows@).to_set();
        &&& ids.contains(g.selected.binding().2.commit) && ids.contains(g.state) && ids.contains(g.component)
        &&& forall|i:int| 0<=i<rows.len() ==> (#[trigger] rows@[i]).1.contents()==table@[rows@[i].0].contents()
    },
{
    let root=g.selected.replacement().commit;
    let rows=crate::closure_load::materialize(table,root)?;
    proof {
        assert(g.records@.dom().contains(root));
        assert(g.records@.dom().contains(g.state));
        assert(table@[root]==g.records@[root]);
        assert(table@[g.state]==g.records@[g.state]);
        let commit=table@[root];
        let state=table@[g.state];
        selected_child(commit,header_graph::STATE@,g.state);
        selected_child(state,header_graph::KV@,g.component);
        let ids=crate::closure_load::row_ids(rows@).to_set();
        use crate::closure_walk::Source;
        let edges=crate::closure_load::Preload(table).edges();
        assert(edges.contains_key(root) && edges.contains_key(g.state));
        assert(edges[root].contains(g.state));
        assert(edges[g.state].contains(g.component));
        assert(ids.contains(g.state));
        assert(ids.contains(g.component));
    }
    Ok(rows)
}
}
