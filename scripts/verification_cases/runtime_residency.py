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
    yield (
        "reverse publication loses the outstanding reservation number", GENERATION,
        lambda s: replace_once(s, "r.identity() == ((id,artifact,scope),*old(next)) &&",
                               "r.identity().0 == (id,artifact,scope) &&"),
        Path("verification/hosted_registry_lookup.rs"),
    )
    registration = Path("crates/astrid-capsule/src/registry/registration.rs")
    for name, clause in [
        ("can return another generation", "ensures runtime == self.runtime"),
        ("can lose the installed handle or owner", "final(instances)@ == old(instances)@.insert(runtime,self.entry)"),
        ("can redirect scoped dispatch", "final(routes)@ == old(routes)@.insert((self.source,self.principal),runtime)"),
        ("can lose reverse provenance", "final(sources)@ == old(sources)@.insert(runtime,self.source)"),
        ("can change the public package name", "final(names)@ == old(names)@.insert(self.source,runtime.identity().0.0)"),
        ("can alter a foreign principal", "final(views)@.remove(self.principal) == old(views)@.remove(self.principal)"),
        ("can discard a sibling package", "final(views)@[self.principal]@ == (if old(views)@.contains_key(self.principal)"),
    ]:
        yield (
            f"runtime registration {name}", registration,
            lambda s, a=clause: replace_once(s, a, a.replace("ensures ", "ensures false ==> ") if a.startswith("ensures ") else "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    sweep = Path("crates/astrid-capsule/src/registry/dependent_views.rs")
    for name, target, clause in [
        ("forgets the retired reverse entry", sweep, "final(sources)@ == old(sources)@.remove(*runtime)"),
        ("forgets the last source user", sweep, "final(names)@ == if old(sources)@.contains_key(*runtime)"),
        ("forgets the replacement source", registration, "final(sources)@ == old(sources)@.insert(*runtime,source)"),
        ("forgets the replacement package", registration, "final(names)@ == old(names)@.insert(source,runtime.identity().0.0)"),
    ]:
        yield (
            f"replacement index {name}", target,
            lambda s, a=clause: replace_once(s, a, "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause in [
        ("loses full-generation route removal", "tear_down ==> final(routes)@ == kept(old(routes)@,*runtime)"),
        ("loses retained peer route preservation", "!tear_down ==> final(routes)@ == if old(sources)@.contains_key(*runtime)"),
    ]:
        yield (
            f"scoped source departure {name}", sweep,
            lambda s, a=clause: replace_once(s, a, a.replace("==>", "&& false ==>")),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause in [
        ("can change the reverse runtime index", "final(sources)@ == if tear_down"),
        ("can remove a shared public source name", "final(names)@ == if tear_down"),
    ]:
        yield (
            f"scoped source departure {name}", sweep,
            lambda s, a=clause: replace_once(s, a, "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weaker in [
        ("can discard a shared artifact", "old(legacy)@\n        } else { kept(old(legacy)@,*artifact) }", "final(legacy)@\n        } else { kept(old(legacy)@,*artifact) }"),
        ("can retain an unused artifact", "else { kept(old(legacy)@,*artifact) }", "else { final(legacy)@ }"),
    ]:
        yield (
            f"legacy source departure {name}", sweep,
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    installed = "final(instances)@ == if tear_down { old(instances)@.remove(*runtime) } else { old(instances)@ }"
    for name, clause in [
        ("can forget to remove the selected generation", "tear_down || final(instances)@ == old(instances)@"),
        ("can alter the retained instance table", "!tear_down || final(instances)@ == old(instances)@.remove(*runtime)"),
    ]:
        yield (
            f"runtime instance departure {name}", sweep,
            lambda s, b=clause: replace_once(s, installed, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weakened in [
        ("can change views on a retained runtime", "else { final(views)@ == before && final(removed)@ == old(removed)@ }",
         "else { final(removed)@ == old(removed)@ }"),
        ("can notify a peer on a retained runtime", "else { final(views)@ == before && final(removed)@ == old(removed)@ }",
         "else { final(views)@ == before }"),
        ("can replace the departing principal prefix", "reported == prior + appended", "true"),
        ("can report a principal twice", "appended.no_duplicates()", "true"),
        ("can omit an affected principal", "appended.contains(p) == (before.contains_key(p)", "appended.contains(p) ==> (before.contains_key(p)"),
        ("can report an unaffected principal", "appended.contains(p) == (before.contains_key(p)", "appended.contains(p) <== (before.contains_key(p)"),
        ("can keep orphan rows", "after.contains_key(p) == (before.contains_key(p)", "after.contains_key(p) <== (before.contains_key(p)"),
        ("can change a surviving package", "after[p])@ == kept(before[p]@,runtime)", "after[p])@.dom() == kept(before[p]@,runtime).dom()"),
    ]:
        yield (
            f"dependent view sweep {name}", sweep,
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, original, weakened in [
        ("loses route membership", "forall|key:(U,P)| #[trigger] final(routes)@.contains_key(key) == (old(routes)", "forall|key:(U,P)| #[trigger] final(routes)@.contains_key(key) ==> (old(routes)"),
        ("loses route values", "forall|key:(U,P)| final(routes)@.contains_key(key) ==> #[trigger] final(routes)@[key] ==\n            if key.0 == source && views@", "forall|key:(U,P)| false && final(routes)@.contains_key(key) ==> #[trigger] final(routes)@[key] ==\n            if key.0 == source && views@"),
    ]:
        yield (
            f"replacement source {name}", Path("crates/astrid-capsule/src/registry/registration.rs"),
            lambda s, a=original, b=weakened: replace_once(s, a, b),
            registration,
        )
    replacement = Path("crates/astrid-capsule/src/registry/generation_replacement.rs")
    for name, clause in [
        ("loses the retired handle", "previous == Some(old(instances)@[retired].capsule)"),
        ("loses the installed generation", "final(instances)@ == old(instances)@.remove(retired).insert(next,self.entry)"),
        ("loses reverse provenance", "final(sources)@ == reverse.insert(next,self.source)"),
        ("loses the public package", "final(names)@ == retained_names.insert(self.source,next.identity().0.0)"),
        ("loses legacy alias retirement", "final(aliases)@ == if exists|id:Id<K,A>|"),
        ("can change aliases when stale", "final(aliases)@ == old(aliases)@"),
    ]:
        yield (
            f"production replacement {name}", replacement,
            lambda s, a=clause: replace_once(s, a, "true" if "if exists" not in a else "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weakened in [
        ("can admit a foreign reservation", "decision == Err(PrincipalRefusal::Reservation)", "true"),
        ("can admit a provider", "Err(PrincipalRefusal::Uplink)\n        } else if", "decision\n        } else if"),
        ("can admit a stale package slot", "Err(PrincipalRefusal::Superseded)\n        } else { Ok(()) }",
         "decision\n        } else { Ok(()) }"),
    ]:
        yield (
            f"principal replacement preflight {name}", replacement,
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause in [
        ("loses the selected forward UID", "ensures out.0 == (if aliases@.contains_key(*alias)"),
        ("loses the selected reverse alias", "out.1 == (if principals@.contains_key(*uid)"),
    ]:
        yield (
            f"directory candidate {name}", Path("crates/astrid-storage/src/principal_directory/binding.rs"),
            lambda s, a=clause: replace_once(s, a, a.replace("out.", "false ==> out.", 1)),
            Path("verification/hosted_registry_lookup.rs"),
        )
    index = Path("crates/astrid-capsule/src/registry/uplink_index.rs")
    for name, clause in [
        ("loses the selected descriptor", "ensures out == if entries@.contains_key(*id)"),
        ("can remove another provider", "final(entries)@ == old(entries)@.restrict("),
    ]:
        yield (
            f"uplink registry {name}", index,
            lambda s, a=clause: replace_once(s, a, a.replace("ensures ", "ensures false ==> ")
                if a.startswith("ensures ") else "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weakened in [
        ("can clear a still-visible package", "old(entries)@ }\n        else {", "final(entries)@ }\n        else {"),
        ("can leave the final package registered", "else { old(entries)@.restrict(old(entries)@.dom().filter(|id:K| old(entries)@[id].0 != *package)) },", "else { final(entries)@ },"),
    ]:
        yield (
            f"uplink registry {name}", index,
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    route_domain = "final(routes)@.contains_key(key) ==\n            ((old(routes)"
    route_value = "forall|key:(U,P)| final(routes)@.contains_key(key) ==> #[trigger] final(routes)@[key] ==\n            if key.0 == source && final(views)@"
    for name, clause, weakened in [
        ("loses scoped membership", route_domain, route_domain.replace(" ==", " ==>")),
        ("loses scoped values", route_value, route_value.replace(" ==> ", " && false ==> ")),
    ]:
        yield (
            f"replacement transition {name}", registration,
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            replacement,
        )
    viewers = Path("crates/astrid-capsule/src/registry/viewers.rs")
    for name, original, weakened in [
        ("can keep a principal runtime", "if !(scope is SystemResident) { Departure::RemoveRuntime }",
         "if !(scope is SystemResident) { out }"),
        ("can retain dependent views when the owner leaves", "else if owner == Some(departing) { Departure::RemoveRuntimeAndViews }",
         "else if owner == Some(departing) { out }"),
        ("can remove a generation with surviving views", "Departure::KeepRuntime\n        } else", "out\n        } else"),
        ("can retain an unreferenced generation", "} else { Departure::RemoveRuntime },", "} else { out },"),
    ]:
        yield (
            f"runtime departure {name}", viewers,
            lambda s, a=original, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    lookup = Path("crates/astrid-capsule/src/registry/view_lookup.rs")
    for name, clause, weaker in [
        ("can omit the matching source route", "old(routes)@.insert((sources@[*runtime],*principal),*runtime)", "final(routes)@"),
        ("can alter routes without a source", "} else { old(routes)@ },", "} else { final(routes)@ },"),
    ]:
        yield (
            f"runtime source attachment {name}", lookup,
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weaker in [
        ("can select an uninstalled handle", "Some(id) => instances@.contains_key(id) &&", "Some(id) =>"),
        ("can select a different package, artifact or scope", "id.identity().0 == (*package,*artifact,super::RuntimeScope::SystemResident),", "true,"),
        ("can miss an installed shared generation", "None => forall|id:RuntimeId<K,A,super::RuntimeScope>|", "None => false ==> forall|id:RuntimeId<K,A,super::RuntimeScope>|"),
    ]:
        yield (
            f"runtime shared selection {name}", lookup,
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause in [
        ("can alter another principal", "final(views)@.remove(principal) == old(views)@.remove(principal)"),
        ("can bind an unrelated package", "final(views)@[principal]@ == (if old(views)@.contains_key(principal)"),
    ]:
        yield (
            f"runtime view publication {name}", lookup,
            lambda s, a=clause: replace_once(s, a, "false ==> " + a),
            Path("verification/hosted_registry_lookup.rs"),
        )
    for name, clause, weakened in [
        ("loses the installed generation and handle",
         "out == match slot(old(views)@,*principal,*capsule)", "instances@.len() == 0 ==> out == match slot(old(views)@,*principal,*capsule)"),
        ("mutates a missing view", "out.is_none() ==> final(views)@ == old(views)@", "true"),
        ("leaves an empty owner row", "after == before.remove(*principal)", "true"),
        ("alters another owner's row", "after.remove(*principal) == before.remove(*principal)", "true"),
        ("loses a sibling package", "after[*principal]@ == remaining", "true"),
    ]:
        yield (
            f"runtime detachment {name}", lookup,
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_registry_lookup.rs"),
        )
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
    for name, original, weakened in [
        ("loses captured scope", "id.identity() == ((package,artifact,running),*old(next))", "id.identity().1 == *old(next)"),
        ("consumes a generation on refusal", "out.is_none() && *final(next) == *old(next)\n        } else {\n            out matches Some(id)", "out.is_none()\n        } else {\n            out matches Some(id)"),
    ]:
        yield (
            f"composed restart preparation {name}", Path("verification/hosted_runtime_residency.rs"),
            lambda s, a=original, b=weakened: replace_once(s, a, b),
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
    slot_values = "forall|k:K| final(view)@.contains_key(k) ==> #[trigger] final(view)@[k] =="
    row_values = "retargeted(old(views)@[p]@,(#[trigger] final(views)@[p])@,*expected,*reserved)"
    for name, clause, weaker, consumer in [
        ("loses the package slot value", slot_values, slot_values.replace(" ==> ", " && false ==> "), swap),
        ("loses the principal row values", row_values, "false ==> " + row_values, registration),
    ]:
        yield (
            f"replacement transition {name}", swap,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), consumer,
        )
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
