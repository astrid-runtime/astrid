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
        ("live publication may lose prior references", "ensures final(references)@.drop_last() == old(references)@,", "ensures true,"),
        ("live publication may name another branch", "branch_label(label,id) && record == target", "true && record == target"),
        ("live publication may name another record", "&& record == target && kind", "&& true && kind"),
        ("live publication may append a non-owning edge", "record == target && kind == ReferenceKind::Owns", "record == target && true"),
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
        ("preserved commit reference can change", "&&& after.take(before.len() as int) == before", "&&& true"),
        ("extra commit links can be appended", "&&& after.len() == before.len() + (if expected.is_some() { 2int } else { 1int })", "&&& after.len() >= before.len() + (if expected.is_some() { 2int } else { 1int })"),
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

    source = Path("crates/astrid-storage/src/content/store/header_graph.rs")
    for name, old, new in [
        ("commit can belong to another lookup", "&&& load.ensures((owner,root.commit),Ok(g.commit))", "&&& true"),
        ("state can belong to another lookup", "&&& load.ensures((owner,g.state_id),Ok(g.state))", "&&& true"),
        ("success can substitute a different matching edge", "&& state_edge(*g.commit) == Some(r)", "&& true"),
        ("failure can substitute a different matching edge", "&& state_edge(*c) == Some(edge)", "&& true"),
        ("state edge can point elsewhere", "r.fields() == (super::commit_candidate::STATE@,g.state_id,super::ReferenceKind::Owns)", "r.fields().0 == super::commit_candidate::STATE@"),
        ("state can carry a different shape", "&&& structural(*g.state,ObjectKind::PrincipalState,v)", "&&& true"),
        ("canonical state edge can be missed", "forall|i:int| #[trigger] positioned(refs@,label@,i) ==> (out matches Some(r) && *r == refs@[i]),", "true,"),
        ("read error may come from another object", "out matches Err(Error::Read(error)) ==> load.ensures((owner,root.commit),Err(error))", "out matches Err(Error::Read(error)) ==> true"),
    ]:
        yield (
            f"content graph {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    component_source = Path("crates/astrid-storage/src/content/store/components.rs")
    component_trace = Path("verification/hosted_header_components.rs")
    for name, old, new in [
        ("can accept non-owning state relations", "&&& kind == super::ReferenceKind::Owns", "&&& true"),
        ("can substitute the selected catalog", "parts.catalog == last_catalog(obs) && forall", "true && forall"),
        ("can substitute the aggregate charge", "parts.other_bytes == #[trigger] total(obs)", "parts.other_bytes >= #[trigger] total(obs)"),
        ("can discard preserved references", "&&& parts.preserved@.map_values(|r:ObjectReference| r.fields()) == refs@.filter(|r:ObjectReference| r.fields().0 != CONTENT@).map_values(|r:ObjectReference| r.fields())", "&&& true"),
        ("can substitute a KV charge", "charge.ensures((owner,Charge::Kv,r,root),Ok(n))", "true"),
        ("can substitute a workspace charge", "charge.ensures((owner,Charge::Workspace,r,root),Ok(n))", "true"),
        ("can report overflow without exceeding the budget", "Ok(n)) && bytes+n > u64::MAX", "Ok(n))"),
        ("can substitute the catalog error", "catalog.ensures((owner,id,root),Err(err))", "true"),
    ]:
        yield (
            f"owner components {name}", component_source,
            lambda s, a=old, b=new: replace_once(s, a, b), component_trace,
        )

    source = Path("crates/astrid-storage/src/content/catalog/summary.rs")
    trace = Path("verification/hosted_catalog_charge.rs")
    for name, old, new in [
        ("can omit the name charge", "s.quota_bytes == logical + name.len()", "s.quota_bytes >= logical"),
        ("can refuse a valid leaf", "out.is_some() == (logical", "out.is_some() ==> (logical"),
        ("can discard a child charge", "s.quota_bytes == left.quota_bytes + right.quota_bytes", "s.quota_bytes >= left.quota_bytes"),
        ("can refuse a valid join", "out.is_some() == (left.logical_bytes", "out.is_some() ==> (left.logical_bytes"),
    ]:
        yield (
            f"catalog accounting {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/quota_transition.rs")
    for name, old, new in [
        ("owner may substitute a refusal", "out == decision(other + previous, other + next, limit)", "out.is_ok() == decision(other + previous, other + next, limit).is_ok()"),
        ("branch may admit an impossible prior charge", "out == if previous > components { Err(Refusal::AccountingOverflow) }", "out == if previous > components { out }"),
        ("over-limit growth may succeed", "else if after > limit && after > before", "else if false"),
        ("over-limit reductions may be refused", "else if after > limit && after > before", "else if after > limit"),
        ("refusal may report a different total", "used:after as u64, limit", "used:0, limit"),
    ]:
        yield (
            f"catalog quota {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )
