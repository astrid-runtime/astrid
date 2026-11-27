//! Observable branch operations for a native workspace binding snapshot.
use crate::workspace_commit::{self, Attachment, WorkspaceCommitOp, Writer};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::{laws_eq::obeys_concrete_eq, std_specs::hash::{hash_map_inv,obeys_key_model}};

verus! {
struct Store<O,B,E> {
    calls: Vec<(WorkspaceCommitOp,O,B)>,
    promotion: Result<(),E>,
    rollback: Result<(),E>,
}

impl<O:Copy,B:Copy,E:Copy> Writer<O,B> for Store<O,B,E> {
    type Error = E;
    closed spec fn calls(&self) -> Seq<(WorkspaceCommitOp,O,B)> { self.calls@ }
    closed spec fn outcome(&self, op: WorkspaceCommitOp, owner: O, branch: B, r: Result<(),E>) -> bool {
        r == match op { WorkspaceCommitOp::Promote => self.promotion, WorkspaceCommitOp::Rollback => self.rollback }
    }
    fn promote(&mut self, owner: O, branch: B) -> Result<(),E> {
        self.calls.push((WorkspaceCommitOp::Promote,owner,branch));
        self.promotion
    }
    fn rollback(&mut self, owner: O, branch: B) -> Result<(),E> {
        self.calls.push((WorkspaceCommitOp::Rollback,owner,branch));
        self.rollback
    }
}

fn finish<O:Copy,B:Copy,E:Copy>(store: &mut Store<O,B,E>, live: bool, bound_uid: Option<[u8;32]>,
    bound_prefix: Option<&[u8]>, uid: [u8;32], prefix: &[u8], op: WorkspaceCommitOp, owner: O, branch: B)
    -> (out: Option<Result<(),E>>)
    ensures if live && bound_uid == Some(uid) && bound_prefix == Some(prefix) {
        &&& final(store).calls@ == old(store).calls@.push((op,owner,branch))
        &&& out == Some(match op { WorkspaceCommitOp::Promote => old(store).promotion,
            WorkspaceCommitOp::Rollback => old(store).rollback })
    } else { out.is_none() && final(store).calls@ == old(store).calls@ },
{
    workspace_commit::finish(Attachment { live, uid: bound_uid, prefix: bound_prefix }, uid, prefix, op, owner, branch, store)
}

type Lease = ([u8;32],u8,u64);

// The requested tuple and the registry record may disagree independently in
// principal UID, storage owner or branch ID. No mismatch can reach a writer.
fn finish_bound<E:Copy>(bindings: &HashMap<[u8;32],Lease>, request: Lease,
    store: &mut Store<u8,u64,E>, live: bool, durable_uid: Option<[u8;32]>,
    durable_prefix: Option<&[u8]>, prefix: &[u8], op: WorkspaceCommitOp)
    -> (out: Option<Result<(),E>>)
    requires hash_map_inv(bindings), obeys_key_model::<[u8;32]>(), obeys_concrete_eq::<[u8;32]>(),
        obeys_concrete_eq::<Lease>(),
    ensures if bindings@.contains_key(request.0) && bindings@[request.0] == request
        && live && durable_uid == Some(request.0) && durable_prefix == Some(prefix) {
        let target = bindings@[request.0];
        &&& final(store).calls@ == old(store).calls@.push((op,target.1,target.2))
        &&& out == Some(match op { WorkspaceCommitOp::Promote => old(store).promotion,
            WorkspaceCommitOp::Rollback => old(store).rollback })
    } else { out.is_none() && final(store).calls@ == old(store).calls@ },
{
    let Ok((uid,owner,branch)) = workspace_commit::lease(bindings,&request.0,&request) else { return None; };
    finish(store,live,durable_uid,durable_prefix,uid,prefix,op,owner,branch)
}
}
