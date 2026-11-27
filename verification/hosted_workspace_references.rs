//! Workspace promotion and rollback operate on concrete durable object references.
use crate::{ObjectId,ObjectReference,ReferenceKind,workspace_references as refs};
use vstd::prelude::*;

verus! {
/// Both observed records must match the supplied loader for this owner and selected ID.
fn decoded_graph<P,E,L>(owner:&P,root:crate::RootState,v:crate::ObjectFormatVersion,load:L,
    table:Ghost<spec_fn(P,ObjectId)->Result<std::sync::Arc<crate::ObjectRecord>,E>>)
    -> (out:Result<crate::header_graph::Graph,crate::header_graph::Error<E>>)
    where L:Fn(&P,ObjectId)->Result<std::sync::Arc<crate::ObjectRecord>,E>,
    requires forall|id:ObjectId| #[trigger] load.requires((owner,id)),
        forall|id:ObjectId,x:Result<std::sync::Arc<crate::ObjectRecord>,E>| #[trigger] load.ensures((owner,id),x) ==> x == (table@)(*owner,id),
    ensures out matches Ok(g) ==> {
        &&& (table@)(*owner,root.commit) == Ok(g.commit)
        &&& g.commit.contents().0 == crate::ObjectKind::Commit && g.commit.contents().1 == v.number()
        &&& g.commit.contents().2.len() == 0 && g.commit.contents().4 == 0 && g.commit.contents().5 == crate::ObjectClass::Metadata
        &&& exists|edge:ObjectReference| g.commit.contents().3.contains(edge) && crate::header_graph::state_edge(*g.commit) == Some(edge) && #[trigger] edge.fields() == (b"state"@,g.state_id,ReferenceKind::Owns)
        &&& (table@)(*owner,g.state_id) == Ok(g.state)
        &&& g.state.contents().0 == crate::ObjectKind::PrincipalState && g.state.contents().1 == v.number()
        &&& g.state.contents().2.len() == 0 && g.state.contents().4 == 0 && g.state.contents().5 == crate::ObjectClass::Metadata
    },
        out matches Err(crate::header_graph::Error::Read(e)) ==> (table@)(*owner,root.commit) == Err(e) ||
            exists|c:std::sync::Arc<crate::ObjectRecord>,edge:ObjectReference|
                (table@)(*owner,root.commit) == Ok(c) && #[trigger] c.contents().3.contains(edge) &&
                crate::header_graph::state_edge(*c) == Some(edge) && edge.fields().0 == b"state"@ && edge.fields().2 == ReferenceKind::Owns && (table@)(*owner,edge.fields().1) == Err(e),
{
    crate::header_graph::read(owner,root,v,load)
}

fn find_canonical_state(refs:&[ObjectReference],i:Ghost<int>) -> (out:Option<&ObjectReference>)
    requires crate::ObjectRecord::labels_ordered(refs@), 0 <= i@ < refs.len(), refs@[i@].fields().0 == b"state"@,
    ensures out matches Some(r) && *r == refs@[i@],
{
    proof {
        assert forall|j:int| 0 <= j < i@ implies #[trigger] refs@[j].fields().0 != b"state"@ &&
            crate::ObjectRecord::label_before(refs@[j].fields().0,b"state"@) by {
            crate::ObjectRecord::ordered_pair(refs@,j,i@);
        }
        assert forall|j:int| i@ < j < refs.len() implies #[trigger] refs@[j].fields().0 != b"state"@ &&
            !crate::ObjectRecord::label_before(refs@[j].fields().0,b"state"@) by {
            crate::ObjectRecord::ordered_pair(refs@,i@,j);
        }
    }
    assert(crate::header_graph::positioned(refs@,b"state"@,i@));
    crate::header_graph::find(refs,b"state")
}

/// Starting at the writer's published root map, distinguish an exact cache
/// hit from every fallback. A miss or stale value must preserve decode errors.
fn sampled_header<P:Ord,H,E,L,D>(roots:&std::collections::BTreeMap<P,crate::RootState>,owner:&P,
    lookup:L,decode:D, entries:Ghost<spec_fn(P,ObjectId)->Option<(Option<crate::RootState>,H)>>)
    -> (out:Result<H,E>)
    where L:FnOnce(&P,ObjectId)->Option<(Option<crate::RootState>,H)>,
          D:FnOnce(&P,Option<crate::RootState>)->Result<H,E>,
    requires vstd::laws_cmp::obeys_cmp::<P>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<P>(),
        vstd::std_specs::btree::btree_map_inv(roots),
        forall|p:&P,id:ObjectId| #[trigger] lookup.requires((p,id)),
        forall|p:&P,id:ObjectId,x:Option<(Option<crate::RootState>,H)>| #[trigger] lookup.ensures((p,id),x) ==> x == (entries@)(*p,id),
        forall|p:&P,r:Option<crate::RootState>| #[trigger] decode.requires((p,r)),
    ensures ({
        let root = if roots@.contains_key(*owner) { Some(roots@[*owner]) } else { None };
        match root {
            Some(r) => match (entries@)(*owner,r.commit) {
                Some((Some(cached),header)) if cached == r => out == Ok(header),
                _ => decode.ensures((owner,root),out),
            },
            None => decode.ensures((owner,None),out),
        }
    }),
{
    let root = crate::root_transition::published(roots,owner);
    crate::header_cache::read(owner,root,lookup,decode)
}

/// Each attempted mutation immediately follows its own sample. Only an explicit
/// commit conflict may be followed by another sample in the same operation.
fn checked_retry<P,I:Copy,H,T,E,B:crate::workspace_retry::Backend<P,I,H,T,E>>(b:&mut B,owner:&P,id:I) -> (out:Result<T,E>)
    ensures ({
        let log = final(b).events();
        let start = old(b).events().len() as int;
        let calls = log.skip(start);
        &&& log.take(start) == old(b).events()
        &&& calls.len() > 0
        &&& forall|k:int| 0 <= k && 2*k+1 < calls.len() ==> match (#[trigger] calls[2*k],calls[2*k+1]) {
            (crate::workspace_retry::Event::Read(p,Ok(header)),crate::workspace_retry::Event::Apply(q,branch,used,result)) =>
                p == *owner && q == *owner && branch == id && used == header &&
                if 2*k+2 < calls.len() { result == Ok(crate::workspace_retry::Step::Conflict) }
                else { result == match out { Ok(t)=>Ok(crate::workspace_retry::Step::Done(t)), Err(e)=>Err(e) } },
            _ => false,
        }
        &&& calls.len()%2 == 1 ==> match out {
            Err(e) => calls.last() == crate::workspace_retry::Event::Read(*owner,Err(e)),
            Ok(_) => false,
        }
    }),
{
    use crate::workspace_retry::{self as retry,Event,Step};
    let ghost start = b.events().len() as int;
    let out = retry::run(b,owner,id);
    proof {
        let calls = b.events().skip(start);
        let n = choose|n:nat| #[trigger] retry::complete(calls,*owner,id,n,out);
        let before = calls.take(2*(n as int));
        assert forall|k:int| 0 <= k && 2*k+1 < calls.len() implies match (#[trigger] calls[2*k],calls[2*k+1]) {
            (Event::Read(p,Ok(header)),Event::Apply(q,branch,used,result)) =>
                p == *owner && q == *owner && branch == id && used == header &&
                if 2*k+2 < calls.len() { result == Ok(Step::Conflict) }
                else { result == match out { Ok(t)=>Ok(Step::Done(t)), Err(e)=>Err(e) } },
            _ => false,
        } by { if k < n { assert(before[2*k] == calls[2*k]); assert(before[2*k+1] == calls[2*k+1]); } }
    }
    out
}

spec fn commit_links(before:Seq<ObjectReference>,links:Seq<ObjectReference>,r:Option<crate::RootState>,state:ObjectId) -> bool {
    &&& links.take(before.len() as int) == before
    &&& links.last().fields() == (b"state"@,state,ReferenceKind::Owns)
    &&& match r {
        None => links.len() == before.len() + 1,
        Some(parent) => links.len() == before.len() + 2 &&
            links[before.len() as int].fields() == (b"parent"@,parent.commit,ReferenceKind::Lineage),
    }
}

/// Check the arguments observed by the native transaction constructor against
/// the header from which the candidate commit references were prepared.
fn encoded_candidate<P,B,E,S>(owner:P,expected:Option<crate::RootState>,prior:Vec<ObjectReference>,state:ObjectId,seal:S)
    -> (out:Result<(P,Option<crate::RootState>,ObjectId,B),E>)
    where S:FnOnce(Vec<ObjectReference>)->Result<(ObjectId,B),E>,
    requires forall|refs:Vec<ObjectReference>| #[trigger] seal.requires((refs,)),
    ensures match out {
        Ok((p,root,commit,records)) => p == owner && root == expected
            && exists|refs:Vec<ObjectReference>| commit_links(prior@,refs@,expected,state)
                && #[trigger] seal.ensures((refs,),Ok((commit,records))),
        Err(e) => exists|refs:Vec<ObjectReference>| commit_links(prior@,refs@,expected,state)
            && #[trigger] seal.ensures((refs,),Err(e)),
    },
{
    let candidate = crate::commit_candidate::Candidate::new(owner,expected,prior,state);
    assert(commit_links(prior@,candidate.parts().2@,expected,state));
    candidate.seal(seal)
}

proof fn normalized(input:Seq<ObjectReference>, id:[u8;16])
    ensures ({
        let keep = |r:ObjectReference| refs::keep(r,id);
        input.filter(keep).filter(keep) == input.filter(keep)
    }),
    decreases input.len(),
{
    reveal_with_fuel(Seq::<_>::filter,3);
    if input.len() > 0 {
        let keep = |r:ObjectReference| refs::keep(r,id);
        normalized(input.drop_last(),id);
        if keep(input.last()) {
            let filtered = input.drop_last().filter(keep);
            assert(filtered.push(input.last()).drop_last() =~= filtered);
            assert(filtered.push(input.last()).last() == input.last());
        }
    }
}

// Operate on an arbitrary (possibly recovered) header with duplicate labels,
// unrelated targets, or several labels referring to one immutable object.
fn promote_then_drop(records: &mut Vec<ObjectReference>, id:[u8;16], target:ObjectId)
    -> (published: ObjectId)
    ensures ({
        let keep = |r:ObjectReference| !refs::branch_label(r.fields().0,id) && !refs::receipt_label(r.fields().0,id);
        final(records)@ == old(records)@.filter(keep) && published == target
    }),
{
    let ghost original = records@;
    let ghost keep = |r:ObjectReference| refs::keep(r,id);
    refs::rewrite(records,id,Some(target));
    let ghost receipt = choose|r:ObjectReference| refs::promotion(r,id,target)
        && records@ == #[trigger] original.filter(keep).push(r);
    let last = &records[records.len()-1];
    let published = last.target();
    assert(last.fields().2 == ReferenceKind::Owns);
    assert(refs::receipt_label(last.fields().0,id));
    let ghost with_receipt = records@;
    refs::rewrite(records,id,None);
    proof {
        reveal_with_fuel(Seq::<_>::filter,2);
        normalized(original,id);
        assert(!keep(receipt));
        assert(with_receipt.drop_last() =~= original.filter(keep));
        assert(with_receipt.last() == receipt);
        assert(records@ == original.filter(keep));
        assert(keep =~= |r:ObjectReference| !refs::branch_label(r.fields().0,id) && !refs::receipt_label(r.fields().0,id));

    }
    published
}

/// Decode the exact durable edge appended by branch creation and catalog publication.
fn recover_live(records:&mut Vec<ObjectReference>,id:[u8;16],target:ObjectId)
    -> (out:(Option<[u8;16]>,Option<[u8;16]>,ObjectId))
    ensures out == (Some(id),None,target),
        final(records)@.len() == old(records)@.len()+1,
        final(records)@.drop_last() == old(records)@,
        final(records)@.last().fields().2 == ReferenceKind::Owns,
{
    refs::push_live(records,id,target);
    let edge = &records[records.len()-1];
    let bytes = edge.label_bytes();
    assert forall|other:[u8;16]| !refs::receipt_label(bytes@,other) by {
        if refs::receipt_label(bytes@,other) {
            assert(bytes@.take(19).take(10) =~= bytes@.take(10));
        }
    }
    let receipt = refs::receipt(bytes);
    if let Some(other) = receipt { assert(refs::receipt_label(bytes@,other)); }
    (refs::branch(bytes),receipt,edge.target())
}

// Canonical encoding and actual recovery lookup must agree and a generated
// receipt must never be accepted as a live branch label.
fn recover_promoted(id:[u8;16]) -> (out:(Option<[u8;16]>,Option<[u8;16]>))
    ensures out == (None,Some(id)),
{
    let label = refs::encode_receipt(id);
    let live = refs::branch(&label);
    assert forall|other:[u8;16]| !refs::branch_label(label@,other) by {}
    if let Some(other) = live { assert(refs::branch_label(label@,other)); }
    (live,refs::receipt(&label))
}
}
