//! Workspace promotion and rollback operate on concrete durable object references.
use crate::{ObjectId,ObjectReference,ReferenceKind,workspace_references as refs};
use vstd::prelude::*;

verus! {
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
