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

fn metadata(mut refs:Vec<ObjectReference>,kind:ObjectKind,v:ObjectFormatVersion) -> (out:Option<ObjectRecord>)
    requires vstd::laws_cmp::obeys_cmp::<ObjectReference>(),
    ensures out matches Some(r) ==> header_graph::structural(r,kind,v) &&
        ObjectRecord::labels_ordered(r.contents().3) && r.contents().3.to_multiset()==refs@.to_multiset(),
        out.is_none() ==> exists|sorted:Seq<ObjectReference>| sorted.to_multiset()==refs@.to_multiset() &&
            !ObjectRecord::labels_ordered(sorted),
{
    let ghost original=refs@;
    refs.as_mut_slice().sort();
    let ghost sorted=refs@;
    let out=ObjectRecord::from_fields(kind,v,Vec::new(),refs,0,ObjectClass::Metadata);
    proof {
        if out.is_none() {
            assert(exists|rows:Seq<ObjectReference>| rows.to_multiset()==original.to_multiset() &&
                !ObjectRecord::labels_ordered(rows)) by {assert(!ObjectRecord::labels_ordered(sorted));}
        }
    }
    out
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
}
