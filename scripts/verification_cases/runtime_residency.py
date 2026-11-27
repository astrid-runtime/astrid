"""Mutations of operator runtime classification, owner selection and identity issuance."""
from pathlib import Path

from .common import GENERATION, replace_once


def defects():
    for name, original in [
        ("loses the retiring gate identity", "ensures retired@.id() == self.location()"),
        ("loses permanent refusal", "witness.is_some() ==> byte == RETIRED"),
    ]:
        yield (
            f"route retirement witness {name}", Path("crates/astrid-events/src/route/gate/state.rs"),
            lambda s, a=original: replace_once(s, a, "ensures true" if a.startswith("ensures ") else "true"),
            Path("verification/hosted_route_retirement.rs"),
        )
    lookup = Path("crates/astrid-capsule/src/registry/view_lookup.rs")
    for name, original, weakened in [
        ("loses equality with the captured generation", "ensures yes == (slot", "ensures yes ==> (slot"),
        ("admits a stale generation", "ensures yes == (slot", "ensures yes <== (slot"),
        ("loses selected instance", "ensures out == match slot(views@,*principal,*capsule) {\n", "ensures instances@.len() == 0 ==> out == match slot(views@,*principal,*capsule) {\n"),
    ]:
        yield (
            f"registry view lookup {name}", lookup,
            lambda s, a=original, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause in [
        ("loses the installed handle and identity", "_ => RestartSnapshot::Current(v,instances@[v].capsule),"),
        ("admits a superseded caller", "Some(e) if *e != v => RestartSnapshot::Superseded,"),
        ("cannot distinguish a missing instance", "_ => RestartSnapshot::Missing,"),
    ]:
        yield (
            f"restart snapshot {name}", lookup,
            lambda s, c=clause: replace_once(s, c, c.split("=>")[0] + "=> out,"),
            Path("verification/hosted_registry_lookup.rs"),
        )
    viewers = Path("crates/astrid-capsule/src/registry/viewers.rs")
    yield (
        "restart viewer selection can ignore a matching slot", viewers,
        lambda s: replace_once(s, "ensures found == view@.values()", "ensures found ==> view@.values()"),
        viewers,
    )
    for name, original, weakened in [
        ("omits an attached principal", "out@.contains(p) <==>\n        views@", "out@.contains(p) ==>\n        views@"),
        ("admits an unrelated principal", "out@.contains(p) <==>\n        views@", "out@.contains(p) <==\n        views@"),
        ("repeats a principal", "ensures out@.no_duplicates(),", "ensures true,"),
    ]:
        yield (
            f"restart viewer selection {name}", viewers,
            lambda s, a=original, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_runtime_residency.rs"),
        )
    swap = Path("crates/astrid-capsule/src/registry/instance_swap.rs")
    for name, original, weaker in [
        ("can rewrite an unrelated view", "ensures *final(slot) == if *old(slot) == *expected { *reserved } else { *old(slot) }", "ensures *old(slot) == *expected ==> *final(slot) == *reserved"),
        ("loses retired handle", "out == Some(before[*expected].capsule)", "out.is_some()"),
        ("loses installed handle", "ensures out == if instances@.contains_key", "ensures false ==> out == if instances@.contains_key"),
        ("loses installed entry", "final(instances)@ == before.remove(*expected).insert(reserved, Entry { capsule, owner_alias })", "true"),
        ("permits stale retry to change another entry", "out.is_none() && final(instances)@ == before", "out.is_none()"),
    ]:
        yield (
            f"registry replacement {name}", swap,
            lambda s, a=original, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_runtime_residency.rs"),
        )
    residency = Path("crates/astrid-kernel/src/runtime_residency.rs")
    for name, original, changed in [
        ("loses unapproved provider refusal", "ensures out == if uplinks.provides", "ensures allowed ==> out == if uplinks.provides"),
        ("loses MCP declaration refusal", "ensures out == if uplinks.provides", "ensures !has_servers ==> out == if uplinks.provides"),
        ("allows a principal without a UID", "Ok(None) => false", "Ok(None) => true"),
        ("loses the bound UID", "lookup.ensures((principal,expected), Ok(uid))", "true"),
        ("loses the directory error", "lookup.ensures((principal,expected), Err(e))", "true"),
    ]:
        yield (
            f"runtime residency {name}", residency,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_runtime_residency.rs"),
        )
    yield (
        "restart reservation scope can discard a mismatch", residency,
        lambda s: replace_once(s, "ensures out == if installed == *running", "ensures installed == *running ==> out == if installed == *running"),
        Path("verification/hosted_runtime_residency.rs"),
    )
    yield (
        "runtime issuance loses the admitted scope mapping",
        Path("crates/astrid-capsule/src/registry/runtime_scope.rs"),
        lambda s: replace_once(s, "ensures scope == match owner", "ensures owner.is_none() ==> scope == match owner"),
        Path("verification/hosted_runtime_residency.rs"),
    )
    yield (
        "runtime issuance loses the concrete constructor fields", GENERATION,
        lambda s: replace_once(s, "ensures key.parts() == (capsule_id,artifact,scope)", "ensures true"),
        GENERATION,
    )
    for name, original, changed in [
        ("loses success below exhaustion", "ensures out.is_some() == (*old(next) < u64::MAX)", "ensures true"),
        ("loses exact success advance", "&& *final(next) as int == *old(next) as int + 1", "&& true"),
        ("loses the public runtime key", "ensures value.parts() == self.identity().0", "ensures true"),
        ("loses the public capsule identifier", "ensures *value == self.parts().0", "ensures true"),
        ("loses the public artifact", "ensures *value == self.parts().1", "ensures true"),
        ("loses the public scope", "ensures value == self.parts().2", "ensures true"),
        ("loses the public generation", "ensures value == self.identity().1", "ensures true"),
        ("loses the issued key or generation", "r.identity() == ((id,artifact,scope),*old(next)) &&", "true &&"),
        ("consumes a generation after exhaustion", "out.is_none() ==> *final(next) == *old(next)", "out.is_none() ==> true"),
    ]:
        yield (
            f"runtime issuance {name}", GENERATION,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_runtime_residency.rs"),
        )
    source = Path("crates/astrid-capsule/src/registry/source_lookup.rs")
    for name, original, weakened in [
        ("loses scoped precedence", "out == if instances@.contains_key(v) { Some(instances@[v].capsule) } else { None }", "true"),
        ("accepts ambiguous legacy slots", "Some(handle) => exists|k:K| keys == Set::empty().insert(k) && handle == #[trigger] instances@[view[k]].capsule,", "Some(handle) => true,"),
        ("may refuse a unique live slot", "None => forall|k:K| keys != #[trigger] Set::empty().insert(k),", "None => true,"),
    ]:
        yield (
            f"scoped source {name}", source,
            lambda s, a=original, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_source_lookup.rs"),
        )
