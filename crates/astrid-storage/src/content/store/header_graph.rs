//! Read the owner commit and its owning state edge before decoding components.
#[cfg(verus_keep_ghost)]
use super::ObjectReference;
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, RootState,
    reference_lookup::find,
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

pub(super) open spec fn state_edge(commit: ObjectRecord) -> Option<ObjectReference> {
    let refs = commit.contents().3;
    super::reference_lookup::selected(refs, super::commit_candidate::STATE@, 0, refs.len() as int)
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
