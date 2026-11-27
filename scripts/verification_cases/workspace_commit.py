"""Downstream requirements for the UID-bound workspace finish path."""
from pathlib import Path

from .common import replace_once


def defects():
    source = Path("crates/astrid-capsule/src/context/workspace_commit.rs")
    trace = Path("verification/hosted_workspace_commit.rs")
    for name, old, new in [
        ("can accept a stale lease", "out == if observed == *expected { Ok(observed) } else { Err(LeaseError::Mismatch) }", "observed == *expected ==> out == Ok(observed)"),
        ("can return an arbitrary branch", "{ Ok(observed) } else { Err(LeaseError::Mismatch) }", "{ out } else { Err(LeaseError::Mismatch) }"),
        ("can accept a missing lease", "else { out == Err(LeaseError::Missing) }", "else { true }"),
        ("can omit the storage operation", "final(writer).calls() == old(writer).calls().push((op,owner,branch))", "true"),
        ("can mask a storage error", "&& old(writer).outcome(op,owner,branch,r)", "&& true"),
        ("can write on refusal", "out.is_none() && final(writer).calls() == old(writer).calls()", "out.is_none()"),
    ]:
        yield (
            f"workspace commit {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/workspace/reference_transition.rs")
    trace = Path("verification/hosted_workspace_references.rs")
    for name, old, new in [
        ("recovery may miss a valid receipt", "(out == Some(id)) == #[trigger] receipt_label", "(out == Some(id)) ==> #[trigger] receipt_label"),
        ("live lookup can accept a promotion receipt", "(out == Some(id)) == #[trigger] branch_label", "(out == Some(id)) <== #[trigger] branch_label"),
        ("encoder need not emit a recoverable receipt", "ensures receipt_label(bytes@,id),", "ensures true,"),
        ("receipt may own the wrong object", "&&& reference.fields().1 == target", "&&& true"),
        ("receipt can have the wrong relation kind", "&&& reference.fields().2 == ReferenceKind::Owns", "&&& true"),
        ("rollback can change unrelated references", "None => final(references)@ == survivors", "None => true"),
        ("promotion can change the surviving prefix", "final(references)@ == #[trigger] survivors.push(r)", "final(references)@.len() > 0 && final(references)@.last() == r"),
    ]:
        yield (
            f"workspace references {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/commit_candidate.rs")
    for name, old, new in [
        ("owner can change", "p == self.parts().0 &&", "true &&"),
        ("expected root can change", "r == self.parts().1", "true"),
        ("commit can differ from encoder result", "&& seal.ensures((self.parts().2,),Ok((id,b)))", "&& true"),
        ("error can differ from encoder result", "out matches Err(e) ==> seal.ensures((self.parts().2,),Err(e))", "true"),
        ("parent relation can change", "after[before.len() as int].fields() == (PARENT@,root.commit,ReferenceKind::Lineage)", "after[before.len() as int].fields().1 == root.commit"),
        ("state object can change", "after.last().fields() == (STATE@,state,ReferenceKind::Owns)", "after.last().fields().2 == ReferenceKind::Owns"),
    ]:
        yield (
            f"content commit {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/workspace/retry.rs")
    for name, old, new in [
        ("historical events can be discarded", "ensures final(backend).events().take(old(backend).events().len() as int) == old(backend).events(),", "ensures true,"),
        ("prior attempts can target another branch", "trace[2*i+1] == Event::Apply(owner,id,h,Ok(Step::Conflict))", "true"),
        (
            "completion can use another sampled header",
            "trace[2*(n as int)+1] == Event::Apply(owner,id,h,match out {\n"
            "                Ok(t) => Ok(Step::Done(t)), Err(e) => Err(e),\n            })",
            "match trace[2*(n as int)+1] { Event::Apply(q,key,_,r) => q == owner && key == id && "
            "r == match out { Ok(t) => Ok(Step::Done(t)), Err(e) => Err(e) }, _ => false }",
        ),
        ("failed read may report a different error", "trace[2*(n as int)] == Event::Read(owner,Err(e))", "true"),
    ]:
        yield (
            f"workspace retry {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/header_cache.rs")
    for name, old, new in [
        ("cache hit can return another header", "(out matches Ok(h) && lookup.ensures((owner,r.commit),Some((Some(r),h))))", "out.is_ok()"),
        ("missing published root can mask a decode failure", "None => decode.ensures((owner,root),out)", "None => true"),
        ("stale cache entry can mask a decode failure", "(decode.ensures((owner,root),out) &&", "(true &&"),
        ("matching current entry can be discarded", "h:H| observed != root && #[trigger]", "h:H| true && #[trigger]"),
    ]:
        yield (
            f"content header {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    yield (
        "content header published lookup can select a peer root",
        Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
        lambda s: replace_once(s, "ensures root == if roots@.contains_key(*owner) { Some(roots@[*owner]) } else { None },",
                               "ensures root.is_some() == roots@.contains_key(*owner),"),
        trace,
    )
