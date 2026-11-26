"""Mutations that must fail in a downstream proof consumer."""

from pathlib import Path
from .common import (
    LEASE_CALLBACK,
    replace_once,
)


def consumer_defects():
    """Weaken a production guarantee and require its trace consumer to fail."""
    trace = Path("verification/hosted_wal_writer_trace.rs")
    yield (
        "released WAL root loses its body before owner recovery", trace,
        lambda source: replace_once(source, "&&& recovered@ == root_body@", "&&& true"), trace,
    )
    yield (
        "replay reads another owner's history", trace,
        lambda source: replace_once(source, "lookup(recovered)", "lookup(Owner::System)"), trace,
    )
    yield (
        "replay reconstructs the wrong commit identity", trace,
        lambda source: replace_once(source, "generation:u64::from_le_bytes(r.generation),commit:r.commit",
                                    "generation:u64::from_le_bytes(r.generation),commit:[0;32]"), trace,
    )
    yield (
        "WAL Commit encoding loses its wire contract",
        Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
        lambda source: replace_once(source, "ensures body@ == self.wire()", "ensures true"),
        Path("verification/hosted_wal_writer_trace.rs"),
    )
    yield (
        "file reader loses the bytes preceding EOF",
        Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"),
        lambda source: replace_once(source, "&&& final(destination)@.take(n as int) == input.take(n as int)", "&&& true"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "file reader loses the confirmed payload checksum",
        Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"),
        lambda source: replace_once(source, "exists|p:&[u8]| p@ == final(destination)@ && #[trigger] hash.ensures((MAGIC,envelope.size,p),envelope.checksum)", "true"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "file reader loses the observed file length",
        Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"),
        lambda source: replace_once(source, "out matches Ok(length) ==> length == old(source).image().len() &&", "out matches Ok(length) ==>"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "writer trace loses the reader's exact root span",
        Path("verification/hosted_wal_stream.rs"),
        lambda source: replace_once(source, "scanned.trace@.0 == w.rows && scanned.trace@.1 == w.commit &&", ""),
        Path("verification/hosted_wal_writer_trace.rs"),
    )
    yield (
        "stream scan loses the released descriptor batch",
        Path("crates/astrid-storage/src/engine/durable/wal/transaction.rs"),
        lambda source: replace_once(source, "result matches Ok(Step::Committed(b)) && b == p", "result matches Ok(Step::Committed(_))"),
        Path("verification/hosted_wal_stream.rs"),
    )
    yield (
        "stream scan loses acceptance of valid logical headers",
        Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
        lambda source: replace_once(source, "out.is_ok() == (1 <= self.kind <= 4", "out.is_ok() ==> (1 <= self.kind <= 4"),
        Path("verification/hosted_wal_stream.rs"),
    )
    yield (
        "stream scan loses the exact header kind",
        Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
        lambda source: replace_once(source, "out matches Ok(kind) ==> self.kind == match kind", "out matches Ok(kind) ==> true || self.kind == match kind"),
        Path("verification/hosted_wal_stream.rs"),
    )
    yield (
        "Commit reader loses the physical marker binding",
        Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
        lambda source: replace_once(source, "bytes@ == (physical_wire::Envelope {version:1,size:p.len() as u64,checksum:sum}).wire() + p@", "bytes.len() == physical_wire::WIDTH + p.len()"),
        Path("verification/hosted_wal_model.rs"),
    )
    yield (
        "WAL prefix consumer loses the recovered transcript",
        Path("verification/hosted_wal_binding.rs"),
        lambda source: replace_once(source, "transcript@ == wal_measurement::digest_header(kind,flags,seq,ordinal,body.len() as u64) + body@ &&", ""),
        Path("verification/hosted_wal_model.rs"),
    )
    yield (
        "measured WAL consumer loses the written physical payload",
        Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
        lambda source: replace_once(source, "self.sealed(hash,bytes@) && c == self.parts().3", "c == self.parts().3"),
        Path("verification/hosted_wal_binding.rs"),
    )
    yield (
        "measured WAL consumer loses the digest input at write",
        Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
        lambda source: replace_once(source, "c == self.parts().3 && self.observed(update,value)", "c == self.parts().3"),
        Path("verification/hosted_wal_binding.rs"),
    )
    yield (
        "measured WAL consumer loses the post-write counters",
        Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
        lambda source: replace_once(source, "self.sealed(hash,bytes@) && c == self.parts().3 && self.observed(update,value)", "self.sealed(hash,bytes@) && self.observed(update,value)"),
        Path("verification/hosted_wal_binding.rs"),
    )
    yield (
        "measured WAL consumer loses the reader count binding",
        Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
        lambda source: replace_once(source, "ensures result.0 == self.parts().3, self.observed(update,result.1),", "ensures self.observed(update,result.1),"),
        Path("verification/hosted_wal_binding.rs"),
    )
    yield (
        "WAL physical consumer loses size equality",
        Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
        lambda source: replace_once(source, "e.size == vstd::bytes::spec_u64_from_le_bytes(header@.subrange(12,20))", "true"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "WAL physical consumer loses checksum refusal witness",
        Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
        lambda source: replace_once(source, "!ok && payload.len() == self.size ==>", "false ==>"),
        Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"),
    )
    yield (
        "WAL physical consumer loses first candidate completeness",
        Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
        lambda source: replace_once(source, "forall|j:u64| start <= j < hit ==> #[trigger] observed(probe,j,Ok(Probe::Miss)),", "true,"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "WAL physical consumer loses the resume offset",
        Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
        lambda source: replace_once(source, "ensures out == match active_begin", "ensures true || out == match active_begin"),
        Path("verification/hosted_wal_physical_model.rs"),
    )
    yield (
        "guest uplink consumer loses enqueue argument binding",
        Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
        lambda source: replace_once(source, "&& enqueue.ensures((&guard,&registry@[i],event),value)", "&& true"),
        Path("verification/hosted_uplink_model.rs"),
    )
    yield (
        "guest uplink consumer loses first-match guarantee",
        Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
        lambda source: replace_once(source, "&& forall|j:int| 0 <= j < i ==> #[trigger] skipped(identify,&registry@[j],requested),", ","),
        Path("verification/hosted_uplink_model.rs"),
    )
    yield (
        "guest uplink consumer loses duplicate rejection witness",
        Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
        lambda source: replace_once(source, "result matches Err(RegistrationError::Duplicate) ==> exists|i:int| 0 <= i < old(registry).len()\n            && #[trigger] same.ensures((&old(registry)@[i],&descriptor),true),", ""),
        Path("verification/hosted_uplink_model.rs"),
    )
    yield (
        "KV handoff no longer guarantees the exact sink receipt",
        Path("crates/astrid-capsule/src/engine/wasm/guest_kv.rs"),
        lambda source: replace_once(source, "ensures sink.ensures((&guard, store, effect), result)", "ensures true"),
        Path("verification/hosted_kv_model.rs"),
    )
    yield (
        "WAL replay contract loses idempotent publication",
        Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
        lambda source: replace_once(
            replace_once(source, "(decision is AlreadyPublished) == matches_root(actual, Some(replacement)),", ""),
            "(decision is Apply) == (!matches_root(actual, Some(replacement)) && matches_root(actual, expected)),",
            "",
        ),
        Path("verification/hosted_kv_model.rs"),
    )
    yield (
        "owner decoding contract omits the recovered UID",
        Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
        lambda source: replace_once(source, "owner matches Some(o) ==> o.bytes() == bytes@,", ""),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("encoder omits the prepared journal postcondition", "&&& encode.ensures((&owner,expected,replacement), Ok(bytes))"),
        ("root publication loses the matching acknowledgement", "publish.ensures((&self.binding().0,self.binding().2),result.1)"),
        ("WAL append loses the matching journal postcondition", "write.ensures((&self.binding().0,self.binding().1,self.binding().2,&self.binding().3),result)"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source, clause=clause: replace_once(source, clause, "&&& true" if clause.startswith("&&&") else "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    yield (
        "WAL parser loses the recovered transition fields",
        Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
        lambda source: replace_once(source, "&&& bytes@.skip(*old(cursor) as int) == prior(expected,scheme) + replacement.wire(scheme)", "&&& true"),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("group frontier loses the staged persistence result", "persist.ensures((&batch,), Ok(group.binding().1))"),
        ("group completion loses the matching frontier receipt", "advance.ensures((self.binding().1,), Ok(frontier))"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    yield (
        "WAL position gate loses the exact admitted body",
        Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
        lambda source: replace_once(source, "result matches Ok(accepted) ==> accepted == body,", ""),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("staged group loses the ordered batch", "group.binding().0 == batch"),
        ("failed persistence loses the original group", "submitted == batch"),
        ("published receipts lose the persisted group", "batch == self.binding().0"),
        ("failed frontier loses the submitted group", "submitted == self.binding().0"),
        ("failed persistence loses the original error", "persist.ensures((&batch,), Err(error))"),
        ("failed frontier loses the original error", "advance.ensures((self.binding().1,), Err(error))"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    for name, clause in [
        ("sync failure loses the unacknowledged batch count", "*final(pending) == if outcome.is_ok() { 0 } else { *old(pending) },"),
        ("sync failure loses writer poisoning", "*final(poisoned) == (*old(poisoned) || outcome matches Err(PublicationError::Sync(_))),"),
        ("sync success loses its connection to the physical sink", "&& exists|w: Result<(),E>| w.is_ok() && #[trigger] sync.ensures((),w)"),
        ("unchanged WAL arena loses its published tail contract", "else if observed == current { Some((current, tail)) }"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "else if observed == current { position }" if clause.startswith("else if") else ""),
            Path("verification/hosted_kv_model.rs"),
        )
    yield (
        "prepared binding loses the mismatched root rejection",
        Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
        lambda source: replace_once(source,
            "outcome.is_ok() == (live@ == saved@ && same_expected(expected,prior) && same(replacement,next))",
            "(live@ == saved@ && same_expected(expected,prior) && same(replacement,next)) ==> outcome.is_ok()"),
        Path("verification/hosted_kv_model.rs"),
    )
    yield (
        "WAL measurement loses the encoded marker witness",
        Path("verification/hosted_wal_model.rs"),
        lambda source: replace_once(source, "out matches Some(checked) ==> checked.marker() == marker,", "true,"),
        Path("verification/hosted_wal_model.rs"),
    )
    for name, path, clause, weaker in [
        ("WAL measurement loses the exact stored byte total", "measurement.rs", "c.bytes as int == before.bytes as int + HEADER_LEN as int + body.len(),", "true,"),
        ("WAL measurement loses the digest transcript", "measurement.rs", "h@ == digest_header(kind,flags,sequence,ordinal,body.len() as u64)", "true"),
        ("WAL measurement loses overflow completeness", "measurement.rs", "result.is_ok() == (before.logical", "result.is_ok() ==> (before.logical"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/wal") / path,
            lambda source, clause=clause, weaker=weaker: replace_once(source, clause, weaker),
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
        )
    for name, path, clause, weaker in [
        ("checked WAL Commit loses the observed digest", "commit_wire.rs", "&& finish_digest.ensures((),self.digest)", "&& true"),
        ("committed prefix loses its ordered descriptors", "transaction.rs", "Ok(Step::Committed(b)) && b == p", "Ok(Step::Committed(b))"),
        ("WAL prefix loses its terminal tail guarantee", "transaction.rs", "Event::Tail => result matches Ok(Step::End)", "Event::Tail => true"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/wal") / path,
            lambda source, clause=clause, weaker=weaker: replace_once(source, clause, weaker),
            Path("verification/hosted_wal_model.rs"),
        )
    consumer = Path("verification/hosted_lease_model.rs")
    yield (
        "worker loses the sink's completion guarantee",
        Path("crates/astrid-kernel/src/storage_mount/lease_authority/worker.rs"),
        lambda source: replace_once(source,
            "ensures sink.ensures((&self.binding().0, self.binding().1), result)",
            "ensures true"), consumer,
    )
    for name, clause in [
        ("issued scope", "*bound.parts().1 == self.scope, "),
        ("issued backing", ", *bound.parts().2 == self.backing"),
        ("filesystem scope", "target == self.binding().0.parts().1 &&"),
        ("volume backing", " && backing == self.binding().0.parts().2"),
    ]:
        yield (
            f"callback contract omits {name}", LEASE_CALLBACK,
            lambda source, clause=clause: replace_once(source, clause, ""), consumer,
        )
