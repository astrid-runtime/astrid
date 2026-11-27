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
    for name, original, changed in [
        ("loses the issued key or generation", "make.ensures((key,*old(next)),r) &&", "true &&"),
        ("consumes a generation after exhaustion", "out.is_none() ==> *final(next) == *old(next)", "out.is_none() ==> true"),
    ]:
        yield (
            f"runtime issuance {name}", GENERATION,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_runtime_residency.rs"),
        )
