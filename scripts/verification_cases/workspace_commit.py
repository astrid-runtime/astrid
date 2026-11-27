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
