//! Construct the state and commit records that publish a KV component.
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel, RootState, header_graph,
};
use vstd::prelude::*;

verus! {

pub(crate) const PARENT:&[u8;6]=b"parent";

fn label(bytes:&[u8]) -> (out:ReferenceLabel)
    ensures out.value()@==bytes@,
{
    let mut owned=Vec::with_capacity(bytes.len());
    owned.extend_from_slice(bytes);
    ReferenceLabel::new(owned)
}

fn sorted_metadata(refs:Vec<ObjectReference>,kind:ObjectKind,v:ObjectFormatVersion) -> (out:Option<ObjectRecord>)
    ensures out.is_none()==!ObjectRecord::labels_ordered(refs@),
        out matches Some(r) ==> header_graph::structural(r,kind,v) && r.contents().3==refs@,
{
    ObjectRecord::from_fields(kind,v,Vec::new(),refs,0,ObjectClass::Metadata)
}

fn metadata(mut refs:Vec<ObjectReference>,kind:ObjectKind,v:ObjectFormatVersion) -> (out:Option<ObjectRecord>)
    requires vstd::laws_cmp::obeys_cmp::<ObjectReference>(),
    ensures out matches Some(r) ==> header_graph::structural(r,kind,v) &&
        ObjectRecord::labels_ordered(r.contents().3) && r.contents().3.to_multiset()==refs@.to_multiset(),
{
    refs.as_mut_slice().sort();
    sorted_metadata(refs,kind,v)
}

proof fn selected(refs:Seq<ObjectReference>,edge:ObjectReference)
    requires ObjectRecord::labels_ordered(refs),refs.contains(edge),
    ensures super::reference_lookup::selected(refs,edge.fields().0,0,refs.len() as int)==Some(edge),
{
    let at=refs.index_of(edge);
    super::reference_lookup::canonical_row(refs,at,0,refs.len() as int);
}

pub(crate) fn kv_state(mut refs:Vec<ObjectReference>,head:ObjectId,v:ObjectFormatVersion) -> (out:Option<ObjectRecord>)
    requires vstd::laws_cmp::obeys_cmp::<ObjectReference>(),
    ensures out matches Some(r) ==> header_graph::structural(r,ObjectKind::PrincipalState,v) &&
        (header_graph::kv_edge(r) matches Some(edge) && edge.fields()==(header_graph::KV@,head,ReferenceKind::Owns) &&
            r.contents().3.to_multiset()==refs@.to_multiset().insert(edge)),
{
    let ghost original=refs@;
    let edge=ObjectReference::owns(label(header_graph::KV),head);
    refs.push(edge);
    let record=metadata(refs,ObjectKind::PrincipalState,v)?;
    proof {
        vstd::seq_lib::to_multiset_build(original,edge);
        assert(refs@.to_multiset().count(edge)>0);
        vstd::seq_lib::to_multiset_contains(record.contents().3,edge);
        assert(record.contents().3.contains(edge));
        selected(record.contents().3,edge);
    }
    Some(record)
}

pub(crate) fn commit(mut refs:Vec<ObjectReference>,prior:Option<RootState>,state:ObjectId,v:ObjectFormatVersion) -> (out:Option<ObjectRecord>)
    requires vstd::laws_cmp::obeys_cmp::<ObjectReference>(),
    ensures out matches Some(r) ==> header_graph::structural(r,ObjectKind::Commit,v) &&
        (header_graph::state_edge(r) matches Some(edge) && edge.fields()==(header_graph::STATE@,state,ReferenceKind::Owns) &&
            match prior {
                None=>r.contents().3.to_multiset()==refs@.to_multiset().insert(edge),
                Some(root)=>exists|parent:ObjectReference| parent.fields()==(PARENT@,root.commit,ReferenceKind::Lineage) &&
                    r.contents().3.to_multiset()==refs@.to_multiset().insert(parent).insert(edge),
            }),
{
    let ghost original=refs@;
    if let Some(root)=prior {
        let parent=ObjectReference::new(label(PARENT),root.commit,ReferenceKind::Lineage);
        refs.push(parent);
        proof {vstd::seq_lib::to_multiset_build(original,parent);};
    }
    let ghost prepared=refs@;
    let edge=ObjectReference::owns(label(header_graph::STATE),state);
    refs.push(edge);
    let record=metadata(refs,ObjectKind::Commit,v)?;
    proof {
        vstd::seq_lib::to_multiset_build(prepared,edge);
        vstd::seq_lib::to_multiset_contains(record.contents().3,edge);
        assert(refs@.to_multiset().count(edge)>0);
        assert(record.contents().3.contains(edge));
        selected(record.contents().3,edge);
        if let Some(root)=prior {
            let parent=prepared.last();
            assert(parent.fields()==(PARENT@,root.commit,ReferenceKind::Lineage));
            assert(record.contents().3.to_multiset()==original.to_multiset().insert(parent).insert(edge));
        }
    }
    Some(record)
}
pub(crate) enum StageError<E> {
    State,
    Commit,
    Insert(E),
}

pub(crate) open spec fn staged_edges(state:ObjectRecord,commit:ObjectRecord,head:ObjectId,sid:ObjectId,
    prior:Option<RootState>,v:ObjectFormatVersion,state_refs:Seq<ObjectReference>,commit_refs:Seq<ObjectReference>) -> bool {
        header_graph::structural(state,ObjectKind::PrincipalState,v) && header_graph::structural(commit,ObjectKind::Commit,v) &&
        (header_graph::kv_edge(state) matches Some(e) && e.fields()==(header_graph::KV@,head,ReferenceKind::Owns) &&
            state.contents().3.to_multiset()==state_refs.to_multiset().insert(e)) &&
        (header_graph::state_edge(commit) matches Some(e) && e.fields()==(header_graph::STATE@,sid,ReferenceKind::Owns) &&
            match prior {None=>commit.contents().3.to_multiset()==commit_refs.to_multiset().insert(e),
            Some(root)=>exists|p:ObjectReference| p.fields()==(PARENT@,root.commit,ReferenceKind::Lineage) &&
                commit.contents().3.to_multiset()==commit_refs.to_multiset().insert(p).insert(e)})
}

pub(crate) open spec fn staged<S,E,F:Fn(S,ObjectRecord)->Result<(S,ObjectId),E>>(insert:F,initial:S,mid:S,last:S,
    head:ObjectId,sid:ObjectId,id:ObjectId,state:ObjectRecord,commit:ObjectRecord,prior:Option<RootState>,
    v:ObjectFormatVersion,state_refs:Seq<ObjectReference>,commit_refs:Seq<ObjectReference>) -> bool {
    &&& insert.ensures((initial,state),Ok((mid,sid)))
    &&& insert.ensures((mid,commit),Ok((last,id)))
    &&& staged_edges(state,commit,head,sid,prior,v,state_refs,commit_refs)
}

#[verifier::opaque]
pub(crate) open spec fn finished<S,E,F:Fn(S,ObjectRecord)->Result<(S,ObjectId),E>>(insert:F,initial:S,out:(S,ObjectId),
    head:ObjectId,prior:Option<RootState>,v:ObjectFormatVersion,state_refs:Seq<ObjectReference>,commit_refs:Seq<ObjectReference>) -> bool {
    exists|mid:S,sid:ObjectId,state:ObjectRecord,commit:ObjectRecord|
        #[trigger] staged(insert,initial,mid,out.0,head,sid,out.1,state,commit,prior,v,state_refs,commit_refs)
}

#[verifier::opaque]
pub(crate) open spec fn insert_error<S,E,F:Fn(S,ObjectRecord)->Result<(S,ObjectId),E>>(insert:F,e:E) -> bool {
    exists|s:S,r:ObjectRecord| #[trigger] insert.ensures((s,r),Err(e))
}

/// Stage the state and commit in order on the same transaction context.
/// The commit owns the state object returned by the first insertion.
pub(crate) fn stage_headers<S,E,F>(initial:S,state_refs:Vec<ObjectReference>,commit_refs:Vec<ObjectReference>,
    head:ObjectId,prior:Option<RootState>,v:ObjectFormatVersion,insert:F)
    -> (out:Result<(S,ObjectId),StageError<E>>)
    where F:Fn(S,ObjectRecord)->Result<(S,ObjectId),E>,
    requires vstd::laws_cmp::obeys_cmp::<ObjectReference>(),
        forall|s:S,r:ObjectRecord| #[trigger] insert.requires((s,r)),
    ensures match out {
        Ok(t)=>finished(insert,initial,t,head,prior,v,state_refs@,commit_refs@),
        Err(StageError::Insert(e))=>insert_error(insert,e),
        _=>true,
    },
{
    let Some(state)=kv_state(state_refs,head,v) else {return Err(StageError::State)};
    let (mid,sid)=match insert(initial,state) {
        Ok(t)=>t,
        Err(e)=>{
            assert(insert.ensures((initial,state),Err(e)));
            assert(insert_error(insert,e)) by { reveal(insert_error); }
            return Err(StageError::Insert(e));
        }
    };
    assert(insert.ensures((initial,state),Ok((mid,sid))));
    let Some(commit)=commit(commit_refs,prior,sid,v) else {return Err(StageError::Commit)};
    match insert(mid,commit) {
        Ok(t)=>{
            assert(insert.ensures((mid,commit),Ok((t.0,t.1))));
            assert(staged_edges(state,commit,head,sid,prior,v,state_refs@,commit_refs@));
            assert(staged(insert,initial,mid,t.0,head,sid,t.1,state,commit,prior,v,state_refs@,commit_refs@));
            assert(finished(insert,initial,t,head,prior,v,state_refs@,commit_refs@)) by { reveal(finished); }
            Ok(t)
        },
        Err(e)=>{
            assert(insert.ensures((mid,commit),Err(e)));
            assert(insert_error(insert,e)) by { reveal(insert_error); }
            Err(StageError::Insert(e))
        },
    }
}

}
