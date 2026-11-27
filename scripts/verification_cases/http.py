"""HTTP redirect, request body, and stream-slot proof checks."""
from pathlib import Path

from .common import replace_once


def defects():
    hop = Path("crates/astrid-capsule/src/engine/wasm/host/http/hop.rs")
    hop_trace = Path("verification/hosted_http_hop.rs")
    for name, original, changed in [
        ("loses the admitted operation", "hop.target() == (method,url)", "hop.target().1 == url"),
        ("loses the admitted URL", "hop.target() == (method,url)", "hop.target().0 == method"),
        ("loses the rejection", "Err(e) => check.ensures((method,url),Err(e))", "Err(e) => true"),
        ("loses the request handoff", "ensures build.ensures(self.target(),r)", "ensures true"),
    ]:
        yield (
            f"HTTP hop {name}", hop,
            lambda s, a=original, b=changed: replace_once(s, a, b), hop_trace,
        )
    body = Path("crates/astrid-capsule/src/engine/wasm/host/http/body.rs")
    for name, original, changed in [
        ("loses its captured origin", "read.parts() == (source, outcome)", "read.parts().1 == outcome"),
        ("loses the captured payload", "read.parts() == (source, outcome)", "read.parts().0 == source"),
        ("permits mismatched publication", "&& out == (if matched { Some(self.parts().1) } else { None })",
         "&& (matched ==> out == Some(self.parts().1))"),
    ]:
        yield (
            f"HTTP read observation {name}", body,
            lambda s, a=original, b=changed: replace_once(s, a, b), hop_trace,
        )
    for name, original, changed in [
        ("loses selected chunk", "data.ensures((bytes,), result.0) && result.1.is_none()", "result.1.is_none()"),
        ("allows a completion with a chunk", "data.ensures((bytes,), result.0) && result.1.is_none()", "data.ensures((bytes,), result.0)"),
        ("loses EOF result", "result.0@.len() == 0 && end.ensures((), result.1)", "end.ensures((), result.1)"),
        ("loses transport error mapping", "out.0 matches Err(reason) && failure.ensures((error,), (reason, out.1))", "out.0.is_err()"),
        ("loses successful handoff", "out.0 matches Ok(bytes) && success.ensures((received,), (bytes, out.1))", "out.0.is_ok()"),
        ("allows a timeout receipt", "out.0 == Err(timeout) && out.1.is_none()", "out.0 == Err(timeout)"),
        ("loses EOF receipt", "result.0@.len() == 0 && end.ensures((), result.1)", "result.0@.len() == 0"),
    ]:
        yield (
            f"stream read publication {name}", body,
            lambda s, a=original, b=changed: replace_once(s, a, b), hop_trace,
        )
    for name, original, changed in [
        ("loses cancellation refusal", "_ => result == Err(closed)", "_ => true"),
        ("loses received bytes", "&& bytes@ == body@", ""),
        ("loses transport failure", "result == Err(error)", "true"),
    ]:
        yield (
            f"buffered HTTP response {name}", body,
            lambda s, a=original, b=changed: replace_once(s, a, b), hop_trace,
        )
    for name, original, changed in [
        ("loses alias mismatch refusal", "ensures matches == (reader@", "ensures reader@ == creator@ ==> matches == (reader@"),
        ("loses pinned UID comparison", "ensures matches == (reader@", "ensures expected.is_none() ==> matches == (reader@"),
    ]:
        yield (
            f"stream owner {name}", body,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            hop_trace,
        )
    for name, original, changed in [
        ("loses the owner binding", "if owner && opening && reading { Some(effect(handle)) }",
         "if opening && reading { Some(effect(handle)) }"),
        ("ignores opening retirement", "if owner && opening && reading { Some(effect(handle)) }",
         "if owner && reading { Some(effect(handle)) }"),
        ("ignores reader retirement", "if owner && opening && reading { Some(effect(handle)) }",
         "if owner && opening { Some(effect(handle)) }"),
        ("loses the selected disclosure", "&& effect.ensures((handle,),v)", ""),
    ]:
        yield (
            f"streaming HTTP response {name}", body,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            hop_trace if name == "loses the selected disclosure" else body,
        )
    slots = Path("crates/astrid-capsule/src/engine/wasm/host/http/slots.rs")
    slot_trace = Path("verification/hosted_http_slots.rs")
    for name, original, changed in [
        ("loses the returned handle", "result == Ok(rep) && final(streams)@", "result.is_ok() && final(streams)@"),
        ("loses the occupied response", "result == Err(Refusal::Occupied) && final(streams)@ == before",
         "result == Err(Refusal::Occupied)"),
        ("loses the released response", "removed == if before.contains_key(key) { Some(before[key]) } else { None }",
         "removed.is_some() == before.contains_key(key)"),
        ("loses the destructor update", "final(streams)@ == if deleted {before.remove(key)} else {before}",
         "true"),
    ]:
        yield (
            f"HTTP stream slot {name}", slots,
            lambda s, a=original, b=changed: replace_once(s, a, b), slot_trace,
        )
