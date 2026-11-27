//! Workspace promotion and rollback operate on concrete durable object references.
use crate::{ObjectId,ObjectReference,ReferenceKind,workspace_references as refs};
use vstd::prelude::*;

verus! {
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
