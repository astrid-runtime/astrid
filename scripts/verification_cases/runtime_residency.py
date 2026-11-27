"""Mutations of operator runtime classification, owner selection and identity issuance."""
from pathlib import Path

from .common import GENERATION, replace_once


def defects():
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
