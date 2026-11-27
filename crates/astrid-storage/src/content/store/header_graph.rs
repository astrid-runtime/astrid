//! Read the owner commit and its owning state edge before decoding components.
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    RootState,
};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
pub(super) enum Error<E> { Read(E), Invalid(ObjectId,&'static str) }

pub(super) struct Graph {
    pub(super) commit:Arc<ObjectRecord>,
    pub(super) state_id:ObjectId,
    pub(super) state:Arc<ObjectRecord>,
}

pub(super) open spec fn structural(r:ObjectRecord,kind:ObjectKind,v:ObjectFormatVersion) -> bool {
    let c=r.contents();
    c.0 == kind && c.1 == v.number() && c.2.len() == 0 && c.4 == 0 && c.5 == ObjectClass::Metadata
}

fn validate<E>(record:&ObjectRecord,id:ObjectId,kind:ObjectKind,v:ObjectFormatVersion) -> (out:Result<(),Error<E>>)
    ensures out.is_ok() == structural(*record,kind,v),
        out matches Err(e) ==> (e matches Error::Invalid(object,_) && object == id),
{
    if record.kind().code() != kind.code() || record.format_version().get() != v.get() {
        return Err(Error::Invalid(id,"principal object has wrong kind or version"));
    }
    if !record.canonical_bytes().is_empty() || record.logical_bytes() != 0 || !matches!(record.class(),ObjectClass::Metadata) {
        return Err(Error::Invalid(id,"principal structural object carries payload"));
    }
    Ok(())
}

/// A label in its canonical binary-search position.
pub(super) open spec fn positioned(refs:Seq<ObjectReference>,label:Seq<u8>,i:int) -> bool {
    &&& 0 <= i < refs.len()
    &&& refs[i].fields().0 == label
    &&& forall|j:int| 0 <= j < i ==> #[trigger] refs[j].fields().0 != label && ObjectRecord::label_before(refs[j].fields().0,label)
    &&& forall|j:int| i < j < refs.len() ==> #[trigger] refs[j].fields().0 != label && !ObjectRecord::label_before(refs[j].fields().0,label)
}

/// The exact reference selected by the decoder, even for noncanonical input.
pub(super) open spec fn selected(refs: Seq<ObjectReference>, label: Seq<u8>, lo: int, hi: int)
    -> Option<ObjectReference>
    decreases hi - lo,
{
    if lo < 0 || lo >= hi || hi > refs.len() {
        None
    } else {
        let mid = lo + (hi - lo) / 2;
        let r = refs[mid];
        if r.fields().0 == label { Some(r) }
        else if ObjectRecord::label_before(r.fields().0, label) { selected(refs, label, mid + 1, hi) }
        else { selected(refs, label, lo, mid) }
    }
}

pub(super) open spec fn state_edge(commit: ObjectRecord) -> Option<ObjectReference> {
    let refs = commit.contents().3;
    selected(refs, super::commit_candidate::STATE@, 0, refs.len() as int)
}

pub(super) fn find<'a>(refs:&'a [ObjectReference],label:&[u8]) -> (out:Option<&'a ObjectReference>)
    ensures (match out { Some(r) => Some(*r), None => None }) == selected(refs@,label@,0,refs.len() as int),
        out matches Some(r) ==> refs@.contains(*r) && r.fields().0 == label@,
        forall|i:int| #[trigger] positioned(refs@,label@,i) ==> (out matches Some(r) && *r == refs@[i]),
{
    let mut lo = 0usize;
    let mut hi = refs.len();
    while lo < hi
        invariant lo <= hi <= refs.len(),
            selected(refs@,label@,lo as int,hi as int) == selected(refs@,label@,0,refs.len() as int),
            forall|i:int| #[trigger] positioned(refs@,label@,i) ==> lo <= i < hi,
        decreases hi-lo,
    {
        let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
        let r = &refs[mid];
        if r.label_bytes() == label {
            assert(r.fields().0 =~= label@);
            assert(refs@[mid as int] == *r);
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies i == mid by {
                if i != mid { assert(refs@[mid as int].fields().0 != label@); }
            }
            return Some(r);
        }
        assert(r.fields().0 != label@);
        if r.label_less_than(label) {
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies mid < i by {
                if i < mid { assert(!ObjectRecord::label_before(refs@[mid as int].fields().0,label@)); }
            }
            lo = mid.saturating_add(1);
        } else {
            assert forall|i:int| #[trigger] positioned(refs@,label@,i) implies i < mid by {
                if mid < i { assert(ObjectRecord::label_before(refs@[mid as int].fields().0,label@)); }
            }
            hi = mid;
        }
    }
    None
}

pub(super) fn read<P,E,L>(owner:&P,root:RootState,v:ObjectFormatVersion,load:L) -> (out:Result<Graph,Error<E>>)
    where L:Fn(&P,ObjectId)->Result<Arc<ObjectRecord>,E>,
    requires forall|id:ObjectId| #[trigger] load.requires((owner,id)),
    ensures out matches Ok(g) ==> {
        &&& load.ensures((owner,root.commit),Ok(g.commit))
        &&& structural(*g.commit,ObjectKind::Commit,v)
        &&& exists|r:ObjectReference| g.commit.contents().3.contains(r)
            && state_edge(*g.commit) == Some(r)
            && #[trigger] r.fields() == (super::commit_candidate::STATE@,g.state_id,super::ReferenceKind::Owns)
        &&& load.ensures((owner,g.state_id),Ok(g.state))
        &&& structural(*g.state,ObjectKind::PrincipalState,v)
    },
        out matches Err(Error::Read(error)) ==> load.ensures((owner,root.commit),Err(error)) ||
            exists|c:Arc<ObjectRecord>,edge:ObjectReference|
                #[trigger] load.ensures((owner,root.commit),Ok(c)) && structural(*c,ObjectKind::Commit,v)
                && state_edge(*c) == Some(edge) && c.contents().3.contains(edge) && edge.fields().0 == super::commit_candidate::STATE@
                && edge.fields().2 == super::ReferenceKind::Owns && #[trigger] load.ensures((owner,edge.fields().1),Err(error)),
{
    let commit = match load(owner,root.commit) { Ok(r)=>r, Err(e)=>return Err(Error::Read(e)) };
    validate(&commit,root.commit,ObjectKind::Commit,v)?;
    let Some(edge) = find(commit.references(),super::commit_candidate::STATE) else {
        return Err(Error::Invalid(root.commit,"required principal reference is missing"));
    };
    let Some(state_id) = edge.owning_target() else {
        return Err(Error::Invalid(root.commit,"required principal reference is not owning"));
    };
    assert(commit.contents().3.contains(*edge));
    let state = match load(owner,state_id) { Ok(r)=>r, Err(e)=>return Err(Error::Read(e)) };
    validate(&state,state_id,ObjectKind::PrincipalState,v)?;
    Ok(Graph {commit,state_id,state})
}
}
