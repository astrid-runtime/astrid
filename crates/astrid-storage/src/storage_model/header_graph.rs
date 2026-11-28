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
pub(crate) const STATE: &[u8;5] = b"state";
pub(crate) const KV: &[u8;2] = b"kv";

pub(crate) enum Invalid { KindOrVersion, Payload, MissingState, NonOwningState }
pub(crate) enum Error<E> { Read(E), Invalid(ObjectId,Invalid) }

pub(crate) struct Graph {
    pub(crate) commit:Arc<ObjectRecord>,
    pub(crate) state_id:ObjectId,
    pub(crate) state:Arc<ObjectRecord>,
}

pub(crate) open spec fn structural(r:ObjectRecord,kind:ObjectKind,v:ObjectFormatVersion) -> bool {
    let c=r.contents();
    c.0 == kind && c.1 == v.number() && c.2.len() == 0 && c.4 == 0 && c.5 == ObjectClass::Metadata
}

pub(crate) open spec fn malformed(record:ObjectRecord,kind:ObjectKind,v:ObjectFormatVersion,reason:Invalid) -> bool {
    let f = record.contents();
    match reason {
        Invalid::KindOrVersion => f.0 != kind || f.1 != v.number(),
        Invalid::Payload => f.0 == kind && f.1 == v.number() &&
            (f.2.len() != 0 || f.4 != 0 || f.5 != ObjectClass::Metadata),
        _ => false,
    }
}

fn validate<E>(record:&ObjectRecord,id:ObjectId,kind:ObjectKind,v:ObjectFormatVersion) -> (out:Result<(),Error<E>>)
    ensures out.is_ok() == structural(*record,kind,v),
        out matches Err(e) ==> (e matches Error::Invalid(object,reason) && object == id && malformed(*record,kind,v,reason)),
{
    if record.kind().code() != kind.code() || record.format_version().get() != v.get() {
        return Err(Error::Invalid(id,Invalid::KindOrVersion));
    }
    if !record.canonical_bytes().is_empty() || record.logical_bytes() != 0 || !matches!(record.class(),ObjectClass::Metadata) {
        return Err(Error::Invalid(id,Invalid::Payload));
    }
    Ok(())
}

pub(crate) open spec fn state_edge(commit: ObjectRecord) -> Option<ObjectReference> {
    let refs = commit.contents().3;
    super::reference_lookup::selected(refs, STATE@, 0, refs.len() as int)
}

pub(crate) open spec fn invalid_at<P,E,L:Fn(&P,ObjectId)->Result<Arc<ObjectRecord>,E>>(
    owner:&P,root:RootState,v:ObjectFormatVersion,load:L,id:ObjectId,reason:Invalid,
) -> bool {
    exists|c:Arc<ObjectRecord>| #[trigger] load.ensures((owner,root.commit),Ok(c)) && ({
        ||| id == root.commit && malformed(*c,ObjectKind::Commit,v,reason)
        ||| structural(*c,ObjectKind::Commit,v) && match state_edge(*c) {
            None => id == root.commit && reason is MissingState,
            Some(edge) => if edge.fields().2 != super::ReferenceKind::Owns {
                id == root.commit && reason is NonOwningState
            } else {
                id == edge.fields().1 && exists|state:Arc<ObjectRecord>|
                    #[trigger] load.ensures((owner,id),Ok(state)) && malformed(*state,ObjectKind::PrincipalState,v,reason)
            },
        }
    })
}

pub(crate) fn read<P,E,L>(owner:&P,root:RootState,v:ObjectFormatVersion,load:L) -> (out:Result<Graph,Error<E>>)
    where L:Fn(&P,ObjectId)->Result<Arc<ObjectRecord>,E>,
    requires forall|id:ObjectId| #[trigger] load.requires((owner,id)),
    ensures out matches Ok(g) ==> {
        &&& load.ensures((owner,root.commit),Ok(g.commit))
        &&& structural(*g.commit,ObjectKind::Commit,v)
        &&& exists|r:ObjectReference| g.commit.contents().3.contains(r)
            && state_edge(*g.commit) == Some(r)
            && #[trigger] r.fields() == (STATE@,g.state_id,super::ReferenceKind::Owns)
        &&& load.ensures((owner,g.state_id),Ok(g.state))
        &&& structural(*g.state,ObjectKind::PrincipalState,v)
    },
        out matches Err(Error::Invalid(id,reason)) ==> invalid_at(owner,root,v,load,id,reason),
        out matches Err(Error::Read(error)) ==> load.ensures((owner,root.commit),Err(error)) ||
            exists|c:Arc<ObjectRecord>,edge:ObjectReference|
                #[trigger] load.ensures((owner,root.commit),Ok(c)) && structural(*c,ObjectKind::Commit,v)
                && state_edge(*c) == Some(edge) && c.contents().3.contains(edge) && edge.fields().0 == STATE@
                && edge.fields().2 == super::ReferenceKind::Owns && #[trigger] load.ensures((owner,edge.fields().1),Err(error)),
{
    let commit = match load(owner,root.commit) { Ok(r)=>r, Err(e)=>return Err(Error::Read(e)) };
    validate(&commit,root.commit,ObjectKind::Commit,v)?;
    let Some(edge) = find(commit.references(),STATE) else {
        return Err(Error::Invalid(root.commit,Invalid::MissingState));
    };
    let Some(state_id) = edge.owning_target() else {
        return Err(Error::Invalid(root.commit,Invalid::NonOwningState));
    };
    assert(commit.contents().3.contains(*edge));
    let state = match load(owner,state_id) { Ok(r)=>r, Err(e)=>return Err(Error::Read(e)) };
    validate(&state,state_id,ObjectKind::PrincipalState,v)?;
    Ok(Graph {commit,state_id,state})
}
pub(crate) enum KvError<E> { Graph(Error<E>), NonOwning(ObjectId) }

pub(crate) open spec fn kv_edge(state:ObjectRecord) -> Option<ObjectReference> {
    let refs = state.contents().3;
    super::reference_lookup::selected(refs,KV@,0,refs.len() as int)
}

/// Resolve the optional KV component from the state owned by this root's commit.
pub(crate) fn read_kv<P,E,L>(owner:&P,root:RootState,v:ObjectFormatVersion,load:L)
    -> (out:Result<(Graph,Option<ObjectId>),KvError<E>>)
    where L:Fn(&P,ObjectId)->Result<Arc<ObjectRecord>,E>,
    requires forall|id:ObjectId| #[trigger] load.requires((owner,id)),
    ensures out matches Ok(pair) ==> ({
        let g = pair.0;
        &&& load.ensures((owner,root.commit),Ok(g.commit)) && structural(*g.commit,ObjectKind::Commit,v)
        &&& state_edge(*g.commit) matches Some(r) && r.fields() == (STATE@,g.state_id,super::ReferenceKind::Owns)
        &&& load.ensures((owner,g.state_id),Ok(g.state)) && structural(*g.state,ObjectKind::PrincipalState,v)
        &&& match pair.1 {
            None => kv_edge(*g.state).is_none(),
            Some(id) => kv_edge(*g.state) matches Some(edge) && edge.fields() == (KV@,id,super::ReferenceKind::Owns),
        }
    }),
        out matches Err(KvError::Graph(Error::Invalid(id,reason))) ==> invalid_at(owner,root,v,load,id,reason),
        out matches Err(KvError::Graph(Error::Read(e))) ==> load.ensures((owner,root.commit),Err(e)) ||
            exists|c:Arc<ObjectRecord>| #[trigger] load.ensures((owner,root.commit),Ok(c)) &&
                structural(*c,ObjectKind::Commit,v) && (state_edge(*c) matches Some(edge) &&
                edge.fields().2 == super::ReferenceKind::Owns && load.ensures((owner,edge.fields().1),Err(e))),
        out matches Err(KvError::NonOwning(id)) ==> exists|commit:Arc<ObjectRecord>,state:Arc<ObjectRecord>|
            #[trigger] load.ensures((owner,root.commit),Ok(commit)) && structural(*commit,ObjectKind::Commit,v) &&
            (state_edge(*commit) matches Some(r) && r.fields()==(STATE@,id,super::ReferenceKind::Owns)) &&
            #[trigger] load.ensures((owner,id),Ok(state)) && structural(*state,ObjectKind::PrincipalState,v) &&
            (kv_edge(*state) matches Some(edge) && edge.fields().2 != super::ReferenceKind::Owns),
{
    let g = match read(owner,root,v,load) { Ok(g) => g, Err(e) => return Err(KvError::Graph(e)) };
    let head = match find(g.state.references(),KV) {
        None => None,
        Some(edge) => match edge.owning_target() {
            Some(id) => Some(id),
            None => return Err(KvError::NonOwning(g.state_id)),
        },
    };
    Ok((g,head))
}

}
