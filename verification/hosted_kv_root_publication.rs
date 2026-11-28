//! Bind KV writer edges and marker identity to the commit selected by root CAS.
use crate::{header_graph,header_writer,root_declaration,root_transition,transaction_records,
    ObjectFormatVersion,ObjectId,ObjectRecord,ObjectReference,ReferenceKind,RootState};
use std::collections::BTreeMap;
use vstd::std_specs::iter::IteratorSpec;
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

pub(crate) open spec fn owning_edges(table:Map<ObjectId,ObjectRecord>) -> Map<ObjectId,Set<ObjectId>> {
    table.map_values(|r:ObjectRecord| crate::closure_walk::children(r.contents().3))
}

proof fn recovered_child(source:ObjectRecord,decoded:ObjectRecord,label:Seq<u8>,id:ObjectId)
    requires crate::hosted_record_roundtrip::same_fields(decoded,source),
        crate::reference_lookup::selected(source.contents().3,label,0,source.contents().3.len() as int)
            matches Some(e) && e.fields()==(label,id,ReferenceKind::Owns),
    ensures crate::closure_walk::children(decoded.contents().3).contains(id),
{
    let refs=source.contents().3;
    let edge=crate::reference_lookup::selected(refs,label,0,refs.len() as int).unwrap();
    selected_member(refs,label,0,refs.len() as int,edge);
    let i=choose|i:int| 0<=i<refs.len() && refs[i]==edge;
    assert(decoded.contents().3[i].fields()==edge.fields());
    owning_child(decoded.contents().3,i);
}

/// Run the recovery materializer on a preloaded table. Other retained references
/// can lead outside the declaration. A successful closure must include the
/// selected marker even when those references lead to additional records.
pub(crate) fn materialize<'a,P>(Ghost(g):Ghost<&Graph<P>>,table:&'a BTreeMap<ObjectId,ObjectRecord>,root:ObjectId,v:ObjectFormatVersion)
    -> (out:Result<Vec<(ObjectId,&'a ObjectRecord)>,crate::closure_walk::Failure<ObjectId,ObjectId>>)
    requires root==g.selected.binding().2.commit,g.links(g.selected.binding().0,g.selected.binding().1,g.records@[g.component],v),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),btree_map_inv(table),
        forall|id:ObjectId| #[trigger] g.records@.contains_key(id) ==> table@.contains_key(id) && crate::hosted_record_roundtrip::same_fields(table@[id],g.records@[id]),
    ensures out matches Ok(rows) ==> {
        let ids=crate::closure_load::row_ids(rows@).to_set();
        &&& crate::closure_walk::closed(root,Set::empty(),owning_edges(table@),ids)
        &&& exists|rank:Map<ObjectId,nat>| rank.dom()==ids && #[trigger] crate::closure_walk::ranked(
            owning_edges(table@),Set::empty(),rank)
        &&& ids.subset_of(table@.dom())
        &&& ids.contains(g.selected.binding().2.commit) && ids.contains(g.state) && ids.contains(g.component)
        &&& forall|i:int| 0<=i<rows.len() ==> (#[trigger] rows@[i]).1.contents()==table@[rows@[i].0].contents()
    },
    out matches Err(crate::closure_walk::Failure::Source(id,missing)) ==> id==missing && !table@.contains_key(id),
    out matches Err(crate::closure_walk::Failure::Cycle(k)) ==> crate::closure_walk::reaches(
        owning_edges(table@),Set::empty(),k,k),
    !(out matches Err(crate::closure_walk::Failure::Root(_))),
{
    let rows=crate::closure_load::materialize(table,root)?;
    proof {
        assert(g.records@.dom().contains(root));
        assert(g.records@.dom().contains(g.state));
        recovered_child(g.records@[root],table@[root],header_graph::STATE@,g.state);
        recovered_child(g.records@[g.state],table@[g.state],header_graph::KV@,g.component);
        let ids=crate::closure_load::row_ids(rows@).to_set();
        use crate::closure_walk::Source;
        let edges=crate::closure_load::Preload(table).edges();
        assert(edges.contains_key(root) && edges.contains_key(g.state));
        assert(edges[root].contains(g.state));
        assert(edges[g.state].contains(g.component));
        assert(ids.contains(g.state));
        assert(ids.contains(g.component));
        assert forall|k:ObjectId| ids.contains(k) implies table@.contains_key(k) by {
            let i=choose|i:int| 0<=i<rows.len() && crate::closure_load::row_ids(rows@)[i]==k;
            assert(rows@[i].0==k);
        }
    }
    Ok(rows)
}

spec fn skippable(id:ObjectId,root:ObjectId,state:ObjectId,component:ObjectId,cached:Set<ObjectId>) -> bool {
    id!=root && ((id==state && cached.contains(root)) ||
        (id==component && (cached.contains(root) || cached.contains(state))))
}

/// Use the same incremental owning walk and placement selector as live preparation.
/// A validated ancestor can stop traversal. A fresh uncached path reaches
/// every record even when unrelated declarations are included in the graph.
fn graph_placement<'a,P,T,L:Copy>(g:&Graph<P>,id:ObjectId,table:&BTreeMap<ObjectId,ObjectRecord>,v:ObjectFormatVersion,
    cached:&std::collections::BTreeSet<ObjectId>,pending:&'a BTreeMap<ObjectId,T>,index:&BTreeMap<ObjectId,L>)
    -> (out:Result<crate::closure_load::Placement<'a,T,L>,crate::closure_walk::Failure<ObjectId,ObjectId>>)
    requires g.records@.contains_key(id),g.links(g.selected.binding().0,g.selected.binding().1,g.records@[g.component],v),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),btree_map_inv(table),
        btree_map_inv(pending),btree_map_inv(index),vstd::std_specs::btree::btree_set_inv(cached),
        forall|id:ObjectId| #[trigger] g.records@.contains_key(id) ==> table@.contains_key(id) && table@[id]==g.records@[id],
    ensures out matches Ok(route) ==> match route {
        crate::closure_load::Placement::Unreachable=>skippable(id,g.selected.binding().2.commit,g.state,g.component,cached@),
        crate::closure_load::Placement::Pending(r)=>pending@.contains_key(id) && *r==pending@[id],
        crate::closure_load::Placement::Indexed(loc)=>!pending@.contains_key(id) && index@.contains_key(id) && loc==index@[id],
        crate::closure_load::Placement::NewCommit=>id==g.selected.binding().2.commit && !pending@.contains_key(id) && !index@.contains_key(id),
        crate::closure_load::Placement::NewObject=>id!=g.selected.binding().2.commit && !pending@.contains_key(id) && !index@.contains_key(id),
    },
{
    use crate::closure_walk::Source;
    let mut src=crate::closure_load::Preload(table);
    let root=g.selected.replacement().commit;
    let seen=crate::closure_walk::walk(&mut src,cached,root)?;
    proof {
        let edges=src.edges();
        assert(g.records@.contains_key(root) && g.records@.contains_key(g.state));
        selected_child(table@[root],header_graph::STATE@,g.state);
        selected_child(table@[g.state],header_graph::KV@,g.component);
        assert(edges.contains_key(root) && edges.contains_key(g.state));
        assert(edges[root].contains(g.state) && edges[g.state].contains(g.component));
        if !cached@.contains(root) {
            assert(seen@.contains(g.state));
            if !cached@.contains(g.state) {assert(seen@.contains(g.component));}
        }
        assert(id==root || id==g.state || id==g.component);
    }
    Ok(crate::closure_load::placement(id,root,&seen,pending,index))
}

fn borrowed(record:&ObjectRecord) -> (out:&ObjectRecord) ensures *out==*record {record}

enum Prepared { Omitted, Fresh(crate::closure_load::Fresh,Vec<u8>) }
enum PrepareError<E> { Closure(crate::closure_walk::Failure<ObjectId,ObjectId>), Collision(ObjectId), Read(E) }

/// Prepare any of the three declarations against the same source table and
/// existing destinations. A reused address must contain the declared record.
fn prepare_graph_row<P,L:Copy,E,R>(g:&Graph<P>,id:ObjectId,table:&BTreeMap<ObjectId,ObjectRecord>,v:ObjectFormatVersion,
    cached:&std::collections::BTreeSet<ObjectId>,pending:&BTreeMap<ObjectId,ObjectRecord>,index:&BTreeMap<ObjectId,L>,
    scheme:crate::root_wire::Scheme,read:R)
    -> (out:Result<Prepared,PrepareError<E>>)
    where R:FnOnce(ObjectId,L)->Result<ObjectRecord,E>,
    requires g.links(g.selected.binding().0,g.selected.binding().1,g.records@[g.component],v),g.records@.contains_key(id),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),obeys_concrete_eq::<ObjectRecord>(),
        btree_map_inv(table),btree_map_inv(&g.records),btree_map_inv(pending),btree_map_inv(index),
        vstd::std_specs::btree::btree_set_inv(cached),
        forall|k:ObjectId| #[trigger] g.records@.contains_key(k) ==> table@.contains_key(k) && table@[k]==g.records@[k],
        forall|loc:L| #[trigger] read.requires((id,loc)),
    ensures ({
        let root=g.selected.binding().2.commit;
        let row=g.records@[id];
        match out {
            Ok(Prepared::Omitted)=>skippable(id,root,g.state,g.component,cached@) ||
                (pending@.contains_key(id) && pending@[id]==row) ||
                (!pending@.contains_key(id) && index@.contains_key(id) && read.ensures((id,index@[id]),Ok(row))),
            Ok(Prepared::Fresh(kind,bytes))=>{
                &&& !pending@.contains_key(id) && !index@.contains_key(id)
                &&& (kind is Commit)==(id==root)
                &&& bytes@==crate::recovered_record::encoding(scheme,id,row)
            },
            Err(PrepareError::Read(e))=>!pending@.contains_key(id) && index@.contains_key(id) && read.ensures((id,index@[id]),Err(e)),
            Err(PrepareError::Collision(k))=>k==id && ((pending@.contains_key(id) && pending@[id]!=row) ||
                (!pending@.contains_key(id) && index@.contains_key(id) && exists|r:ObjectRecord| r!=row && #[trigger] read.ensures((id,index@[id]),Ok(r)))),
            Err(PrepareError::Closure(_))=>true,
        }
    }),
{
    let route=match graph_placement(g,id,table,v,cached,pending,index) {Ok(r)=>r,Err(e)=>return Err(PrepareError::Closure(e))};
    let row=g.records.get(&id).unwrap();
    match crate::closure_load::prepare_row(route,id,row,borrowed,read) {
        Ok(None)=>Ok(Prepared::Omitted),
        Ok(Some(kind))=>Ok(Prepared::Fresh(kind,crate::verified_record::encode(scheme,id,row).unwrap())),
        Err(crate::closure_load::PlacementError::Collision(k))=>Err(PrepareError::Collision(k)),
        Err(crate::closure_load::PlacementError::Read(e))=>Err(PrepareError::Read(e)),
    }
}

pub(crate) open spec fn canonical_rows<P>(g:&Graph<P>,rows:Seq<(ObjectId,Vec<u8>)>,scheme:crate::root_wire::Scheme) -> bool {
    rows.len()==g.records.len() &&
        (forall|i:int| 0<=i<rows.len() ==> {
            let row=#[trigger] rows[i];
            &&& g.records@.contains_key(row.0) && row.1@==crate::recovered_record::encoding(scheme,row.0,g.records@[row.0])
        }) && (forall|id:ObjectId| #[trigger] g.records@.contains_key(id) ==> exists|i:int| 0<=i<rows.len() && #[trigger] rows[i].0==id)
}

/// Encode the complete fresh declaration set in the producer map's order.
/// Retained dependencies may already be in the supplied graph, while every
/// declared identity here is new to the pending overlay and arena index.
pub(crate) fn fresh_rows<P>(g:&Graph<P>,table:&BTreeMap<ObjectId,ObjectRecord>,v:ObjectFormatVersion,scheme:crate::root_wire::Scheme)
    -> (out:Result<Vec<(ObjectId,Vec<u8>)>,crate::closure_walk::Failure<ObjectId,ObjectId>>)
    requires g.links(g.selected.binding().0,g.selected.binding().1,g.records@[g.component],v),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),obeys_concrete_eq::<ObjectRecord>(),
        btree_map_inv(table),btree_map_inv(&g.records),
        forall|id:ObjectId| #[trigger] g.records@.contains_key(id) ==> table@.contains_key(id) && table@[id]==g.records@[id],
    ensures out matches Ok(rows) ==> canonical_rows(g,rows@,scheme),
        out matches Err(crate::closure_walk::Failure::Source(k,e)) ==> k==e && !table@.contains_key(k),
        out matches Err(crate::closure_walk::Failure::Cycle(k)) ==> crate::closure_walk::reaches(
            owning_edges(table@),Set::empty(),k,k),
        !(out matches Err(crate::closure_walk::Failure::Root(_))),
{
    use crate::closure_walk::Source;
    let root=g.selected.replacement().commit;
    let empty=std::collections::BTreeSet::new();
    let pending:BTreeMap<ObjectId,ObjectRecord>=BTreeMap::new();
    let index:BTreeMap<ObjectId,()>=BTreeMap::new();
    let mut src=crate::closure_load::Preload(table);
    let seen=crate::closure_walk::walk(&mut src,&empty,root)?;
    proof {
        let edges=src.edges();
        assert(g.records@.contains_key(root) && g.records@.contains_key(g.state));
        selected_child(table@[root],header_graph::STATE@,g.state);
        selected_child(table@[g.state],header_graph::KV@,g.component);
        assert(edges.contains_key(root) && edges.contains_key(g.state));
        assert(edges[root].contains(g.state) && edges[g.state].contains(g.component));
        assert(seen@.contains(root) && seen@.contains(g.state) && seen@.contains(g.component));
        assert(g.records@.dom().subset_of(seen@));
    }
    let mut it=g.records.iter();
    let ghost all=it.remaining();
    let mut rows:Vec<(ObjectId,Vec<u8>)>=Vec::with_capacity(g.records.len());
    loop
        invariant obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),obeys_concrete_eq::<ObjectRecord>(),
            btree_map_inv(&pending),btree_map_inv(&index),pending@.dom().is_empty(),index@.dom().is_empty(),
            vstd::std_specs::btree::btree_set_inv(&seen),g.records@.dom().subset_of(seen@),
            all.len()==g.records.len(),all.unref().to_set()==g.records@.kv_pairs(),
            rows.len()<=all.len(),it.remaining()==all.skip(rows.len() as int),
            forall|j:int| 0<=j<rows.len() ==> (#[trigger] rows@[j]).0==*all[j].0 &&
                rows@[j].1@==crate::recovered_record::encoding(scheme,*all[j].0,*all[j].1),
        decreases g.records.len()-rows.len(),
    {
        let ghost n=rows.len() as int;
        let Some((id,record))=it.next() else {
            assert(n==all.len());
            assert forall|k:ObjectId| #[trigger] g.records@.contains_key(k) implies exists|i:int| 0<=i<rows.len() && #[trigger] rows@[i].0==k by {
                let pair=(k,g.records@[k]);
                assert(all.unref().to_set().contains(pair));
                let i=all.unref().index_of(pair);
                assert(all.unref()[i]==pair && *all[i].0==k && rows@[i].0==k);
            }
            assert forall|j:int| 0<=j<rows.len() implies {
                let row=#[trigger] rows@[j];
                &&& g.records@.contains_key(row.0) && row.1@==crate::recovered_record::encoding(scheme,row.0,g.records@[row.0])
            } by {
                assert(all.unref()[j]==(*all[j].0,*all[j].1));
                assert(g.records@.kv_pairs().contains(all.unref()[j]));
            }
            return Ok(rows);
        };
        assert(all.unref()[n]==(*id,*record));
        assert(g.records@.kv_pairs().contains((*id,*record)));
        let route=crate::closure_load::placement(*id,root,&seen,&pending,&index);
        let read=|_:ObjectId,_:()| -> (r:Result<ObjectRecord,()>) ensures r.is_err() {Err(())};
        let choice=crate::closure_load::prepare_row(route,*id,record,borrowed,read);
        let Ok(Some(_))=choice else {unreached()};
        let bytes=crate::verified_record::encode(scheme,*id,record).unwrap();
        rows.push((*id,bytes));
        assert(it.remaining() =~= all.skip(n+1));
    }
}
}
