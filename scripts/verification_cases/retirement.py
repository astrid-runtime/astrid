"""Downstream mutations for startup fences and principal tracker identity."""

from pathlib import Path

from .common import replace_once


def defects():
    aliases = Path("crates/astrid-storage/src/principal_directory/binding.rs")
    fences = Path("crates/astrid-core/src/principal/retirement.rs")
    for name, path, original, changed in [
        ("loses the retained alias", aliases, "targets[0] == retained,", "true,"),
        ("may omit a distinct live alias", aliases, "else { directory@.get(*uid) },", "else { targets[1] },"),
        ("may duplicate the same alias", aliases, "== retained { None } else", "== retained { targets[1] } else"),
        ("may erase an unrelated fence", fences, "final(set)@ == old(set)@.insert(principal)", "final(set)@.contains(principal)"),
        ("may admit a fenced identity", fences, "closed == set@.contains(*principal)", "closed ==> set@.contains(*principal)"),
    ]:
        yield (
            f"restart fence {name}", path,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_authority_model.rs"),
        )
    cursor = Path("crates/astrid-storage/src/ownership/pending.rs")
    for name, original, changed in [
        ("loses a reservation", "cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)),", "cursor.remaining().contains((&k,&v)) ==> (map@.get(k) == Some(v)),"),
        ("may skip the rest", "(*final(cursor)).remaining() == before.drop_first()", "(*final(cursor)).remaining().len() <= before.drop_first().len()"),
        ("loses a visited UID", "key == *before[0].0 &&", "true &&"),
        ("loses a retained alias", "name == match before[0].1.alias { Some(a) => Some(&a), None => None }", "name.is_some() == before[0].1.alias.is_some()"),
    ]:
        yield (
            f"recovery cursor {name}", cursor,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_retirement_recovery.rs"),
        )
    tracker = Path("crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs")
    for name, original, changed in [
        ("loses guard owner", "guard == if allowed { Some(*principal) } else { None }", "guard.is_some() == allowed"),
        ("may erase another retirement", "final(entries)@.remove(key) == old(entries)@.remove(key),", "true,"),
        ("loses the drain observation", "n == binding(entries@,*key).1", "true"),
        ("may reopen the owner on finish", "binding(final(entries)@,key) == after", "binding(final(entries)@,key).1 == after.1"),
    ]:
        yield (
            f"principal tracker {name}", tracker,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_authority_model.rs"),
        )
