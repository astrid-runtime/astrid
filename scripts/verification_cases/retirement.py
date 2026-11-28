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
            fences if name == "may erase an unrelated fence" else Path("verification/hosted_authority_model.rs"),
        )
    for name, original, changed in [
        ("loses the capability owner", "receipt.owner() == principal,", "true,"),
        ("may skip the capability fence", "final(closed)@ == old(closed)@.insert(principal)", "true"),
        ("may skip the allowance fence", "final(closed)@ == old(closed)@.insert(receipt.owner())", "true"),
        ("may retain the owner's grants", "final(grants)@ == old(grants)@.remove(receipt.owner())", "true"),
    ]:
        yield (
            f"paired restart {name}", fences,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_authority_model.rs"),
        )
    replay = Path("crates/astrid-storage/src/ownership/recovery.rs")
    consumer = Path("verification/hosted_retirement_recovery.rs")
    for name, original, changed, location in [
        ("skips the retained alias", "if let Some(alias) = first {", "if let Some(alias) = None::<A> {", replay),
        ("skips the live alias", "if let Some(alias) = second {", "if let Some(alias) = None::<A> {", replay),
        ("may call another store after the first error", "stopped_at_first_error(old(sink).history(),final(sink).history(),result),", "true,", consumer),
        ("may fail on an unreserved alias", "reserved(reservations@,directory@,#[trigger] final(sink).history()[i].0),", "true || reserved(reservations@,directory@,#[trigger] final(sink).history()[i].0),", consumer),
        ("loses the failure result", "final(sink).failure() == (match result { Ok(()) => None, Err(e) => Some(e) })", "true", consumer),
        ("may omit an unrelated bucket", "else { old(sink).authority(key) },\n{", "else { final(sink).authority(key) },\n{", consumer),
    ]:
        yield (
            f"production replay {name}", replay,
            lambda s, a=original, b=changed: replace_once(s, a, b), location,
        )
    cas = Path("crates/astrid-storage/src/kv/tree/context/replacement.rs")
    for label, before, after in [
        ("observed value", "Self::assign(key,previous,new);\n        Ok(((),rows,changed))", "Self::assign(key,None,new);\n        Ok(((),rows,changed))"),
        ("target", "let previous=read(header,key)?;", "let previous=read(header,&[])?;"),
        ("equal value", "return (Vec::new(),false);", "return (Vec::new(),true);"),
    ]:
        yield (
            f"revocation point write loses {label}", cas,
            lambda s, a=before, b=after: replace_once(s, a, b), cas,
        )
    for name, original, changed in [
        ("comparison result", "out.0 == (prior == expected)", "true"),
        ("change decision", "out.2 == (prior == expected && prior != Some(new))", "true"),
        ("replacement count", "out.1.len() == if out.2 {1int} else {0int}", "true"),
        ("replacement address and bytes", "out.2 ==> out.1@[0].fields()", "false ==> out.1@[0].fields()"),
        ("read failure", "Err(e) => read.ensures((header,key),Err(e))", "Err(e) => true"),
        ("read provenance", "#[trigger] read.ensures((header,key),Ok(old)) &&", "true &&"),
    ]:
        yield (
            f"ownership graph CAS loses {name}", cas,
            lambda s, a=original, b=changed: replace_once(s, a, b), consumer,
        )
    cursor = Path("crates/astrid-storage/src/ownership/pending.rs")
    for name, original, changed in [
        ("candidate identity", "final(rows)@ == old(rows)@.insert(uid,match before", "final(rows)@.contains_key(uid) || final(rows)@ == old(rows)@.insert(uid,match before"),
        ("alias compatibility", "&&& before matches Some(r) ==> !(r.alias matches Some(a) && (alias matches Some(b) && a != b))", "&&& true"),
        ("fresh admission", "before.is_none() ==> exists|r:Result<(),E>|", "false ==> exists|r:Result<(),E>|"),
        ("error atomicity", "out.is_err() ==> final(rows)@ == old(rows)@", "true"),
        ("conflict identity", "old(rows)@[uid].alias == Some(a) && (requested matches", "(requested matches"),
        ("admission error", "!old(rows)@.contains_key(uid) && admit.ensures((&*old(rows),),Err(e))", "true"),
    ]:
        yield (
            f"retirement candidate loses {name}", cursor,
            lambda s, a=original, b=changed: replace_once(s, a, b), consumer,
        )
    for name, original, changed in [
        ("loses a reservation", "cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)),", "cursor.remaining().contains((&k,&v)) ==> (map@.get(k) == Some(v)),"),
        ("may skip the rest", "(*final(cursor)).remaining() == before.drop_first()", "(*final(cursor)).remaining().len() <= before.drop_first().len()"),
        ("loses a visited UID", "key == *before[0].0 &&", "true &&"),
        ("loses a retained alias", "name == match before[0].1.alias { Some(a) => Some(&a), None => None }", "name.is_some() == before[0].1.alias.is_some()"),
    ]:
        yield (
            f"recovery cursor {name}", cursor,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            replay,
        )
    for name, original, changed in [
        ("loses another grant bucket", "final(grants)@ == old(grants)@.remove(*principal)", "!final(grants)@.contains_key(*principal)"),
        ("may release another fence", "final(set)@ == old(set)@.remove(*principal)", "!final(set)@.contains(*principal)"),
    ]:
        yield (
            f"completed retirement {name}", fences,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_retirement_recovery.rs") if "fence" in name else fences,
        )
    tracker = Path("crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs")
    for name, original, changed in [
        ("may retain a drained idle entry", "final(entries)@.contains_key(key) == (after.0 || after.1 > 0)", "(after.0 || after.1 > 0) ==> final(entries)@.contains_key(key)"),
        ("drain may erase another principal", "&&& final(entries)@.remove(key) == old(entries)@.remove(key)\n", "&&& true\n"),
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
