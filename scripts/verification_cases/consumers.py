"""Mutations that must fail in a downstream proof consumer."""

from pathlib import Path
from .common import (
    LEASE_CALLBACK,
    replace_once,
)


def consumer_defects():
    """Weaken a production guarantee and require its trace consumer to fail."""
    walk_source = Path("crates/astrid-storage/src/engine/durable/closure_walk.rs")
    yield (
        "closure diagnostic loses the cycle through its reported object", walk_source,
        lambda s: replace_once(s, "&& reaches(old(source).edges(),cached@,k,k) &&", "&& true &&"),
        Path("verification/hosted_closure_model.rs"),
    )
    record = Path("crates/astrid-storage/src/engine/durable/format/verified_record.rs")
    record_trace = Path("verification/hosted_record_model.rs")
    overlay = Path("crates/astrid-storage/src/engine/durable/wal/overlay_object.rs")
    for name, clause, weaker in [
        ("loses acceptance of equal frames", "out.is_ok() == ((*old(self).payload)@ == (*incoming.payload)@)", "out.is_ok() ==> ((*old(self).payload)@ == (*incoming.payload)@)"),
        ("loses the retained record", "final(self).record == old(self).record", "true"),
        ("loses direct metadata on upgrade", "final(self).direct == incoming.direct", "true"),
    ]:
        yield (
            f"pending WAL merge {name}", overlay,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), record_trace,
        )
    for name, clause, weaker in [
        ("forgets the new entry", "out.is_ok() && final(objects)@ == old(objects)@.insert(id, candidate)", "out.is_ok()"),
        ("forgets other names on a duplicate", "final(objects)@ == old(objects)@.insert(id, retained)", "final(objects)@.contains_key(id)"),
        ("drops staged placement", "out.location == Some(location) && out.direct == direct", "out.direct == direct"),
        ("allows a prepared placement", "out.location.is_none() && out.direct.is_none()", "out.direct.is_none()"),
    ]:
        yield (
            f"pending WAL installation {name}", overlay,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), record_trace,
        )
    for name, clause, weaker, target in [
        ("accepts a trailing byte", "if cursor != bytes.len() {return Err(BodyError::Trailing);}", "", record),
        ("forgets the canonical bytes", "fields.2 == bytes.subrange(data,refs)", "true", record_trace),
        ("loses relation-code provenance", "forall|i:nat| i < fields.3.len() ==> #[trigger] stored_reference(bytes,position(bytes,refs,i),fields.3[i as int])", "true", record_trace),
        ("loses the exact payload retained", "name == id && (*retained)@ == (**frame)@ &&", "name == id &&", record_trace),
        ("forgets positive admission for valid references", "!leaf_body((**frame)@,40) && (complete_body((**frame)@,40,scheme) ==> e is Allocation)", "!leaf_body((**frame)@,40)", record_trace),
        ("permits a spurious wrong name", "id.digest() != (**frame)@.subrange(8,40)", "true", record_trace),
    ]:
        yield (
            f"canonical record {name}", record,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )
    yield (
        "canonical record forgets strict label ordering", record,
        lambda s: replace_once(s, "&&& ObjectRecord::labels_ordered(fields.3)", "&&& true"), record_trace,
    )
    roundtrip = Path("verification/hosted_record_roundtrip.rs")
    for name, clause, weaker in [
        ("drops the writer field layout", "bytes@ == scheme.algorithm@ + scheme.construction@ + seq![32u8,0u8,0u8,0u8] + id.digest() +\n            header_wire(f.0,f.1,f.5) + payload_wire(f.4,f.2,f.3.len() as usize) + reference_prefix(f.3,f.3.len(),scheme)", "true"),
        ("loses full body acceptance", "tag(frame@,0,scheme) && !leaf_body(frame@,40) &&\n            (complete_body(frame@,40,scheme) ==> e is Allocation)", "tag(frame@,0,scheme) && !leaf_body(frame@,40)"),
    ]:
        yield (
            f"object round trip {name}", record,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), roundtrip,
        )
    layers = Path("crates/astrid-storage/src/engine/durable/closure_load.rs")
    transactions = Path("crates/astrid-storage/src/engine/transaction_records.rs")
    closure_trace = Path("verification/hosted_closure_model.rs")
    for name, original, changed, target in [
        ("admits an authority match for unsealed input", "Self::Untrusted => false", "Self::Untrusted => true", transactions),
        ("returns a foreign checkpoint", "Self::Rechecked => None}", "Self::Rechecked => value.take()}", transactions),
        ("loses matching engine provenance", "Ok(Admission::SameEngine) => self.compared(current,same,true)", "Ok(Admission::SameEngine) => true", closure_trace),
        ("loses identity checking on foreign admission", "0 <= i < rows.len() ==> #[trigger] authentic(rows@[i],identify)", "false ==> #[trigger] authentic(rows@[i],identify)", closure_trace),
        ("forgets a supplied row after deduplication", "btree_map_inv(&map) && represents(map@,records@)", "btree_map_inv(&map)", closure_trace),
        ("reports a collision for identical declarations", "Some(existing) if existing == &record => Ok(id)", "Some(existing) if existing == &record => Err(id)", transactions),
        ("loses the conflicting values on rejection", "records@[i].1 != records@[j].1", "true", closure_trace),
        ("misbinds the newly named record", "row.1 == record && derive_id.ensures((&row.1,),row.0)", "true", closure_trace),
    ]:
        yield (
            f"transaction staging {name}", transactions,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    def pending_before_incoming(source):
        incoming = """    if let Some(record) = layers.incoming.get(&id) {
        return Ok(from_incoming(record));
    }
"""
        pending = """    let pending = match layers.pending {Some(table) => table.get(&id), None => None};
    if let Some(record) = pending {
        return Ok(from_pending(record));
    }
"""
        return replace_once(source, incoming + pending, pending + incoming)

    yield ("closure lookup substitutes pending for incoming", layers, pending_before_incoming, layers)
    yield (
        "closure lookup treats an evidence reference as owned", layers,
        lambda s: replace_once(s, "self.owning_target()", "Some(self.target())"), walk_source,
    )
    yield (
        "closure authentication omits the last transaction row", transactions,
        lambda s: replace_once(s, "while i < records.len()", "while i < records.len().saturating_sub(1)"), transactions,
    )
    yield (
        "closure authentication forgets the first mismatched declaration", transactions,
        lambda s: replace_once(s, "name == records@[i].0 &&", "true &&"), closure_trace,
    )
    for name, original, changed in [
        ("drops the incoming record", "from_incoming.ensures((&layers.incoming@[id],),record)", "true"),
        ("drops the pending record", "from_pending.ensures((&layers.pending.unwrap()@[id],),record)", "true"),
        ("loses the physical location and requested id", "from_index.ensures((id,&layers.index@[id]),out)", "true"),
        ("loses the missing identity", "missing.ensures((id,),error)", "true"),
    ]:
        yield (
            f"closure lookup {name}", layers,
            lambda s, a=original, b=changed: replace_once(s, a, b), closure_trace,
        )
    def admit_zero_version(source):
        for original, changed in [
            ("kind < 18 && version != 0 &&", "kind < 18 &&"),
            ("v == version && v != 0 &&", "v == version &&"),
            ("if version == 0 {return Err(HeaderError::Version);}", ""),
        ]:
            source = replace_once(source, original, changed)
        return source

    yield ("arena storage admits zero version", record, admit_zero_version, record_trace)
    for name, original, changed in [
        ("payload admits truncated canonical data", "out.is_ok() == (end <= bytes.len()", "out.is_ok() <== (end <= bytes.len()"),
        ("decoded edge loses concrete label", "r.fields().0 == bytes.subrange(at+8,t)", "true"),
        ("decoded edge loses concrete target", "r.fields().1.digest() == bytes.subrange(t+8,t+40)", "true"),
        ("decoded edge loses concrete kind", "meaning(bytes[t+40],r.fields().2)", "true"),
    ]:
        yield (
            f"arena storage {name}", record,
            lambda s, a=original, b=changed: replace_once(s, a, b), record_trace,
        )
    for name, original, changed in [
        ("kind", "k.wire_code() == kind &&", "true &&"),
        ("class", "c.wire_code() == bytes@[start+4] &&", "true &&"),
        ("version", "v == version &&", "true &&"),
    ]:
        yield (
            f"arena header loses the stored {name}", record,
            lambda s, a=original, b=changed: replace_once(s, a, b), record_trace,
        )
    for name, original, changed, target in [
        ("writes logical size as reference count", "little_endian(refs)", "little_endian(logical)", record),
        ("loses canonical payload contents", "data@ == bytes@.subrange(start+24,end)", "data.len() == end-start-24", record_trace),
        ("loses reference count", "refs == count &&", "true &&", record_trace),
        ("loses first reference offset", "*final(cursor) as int == end", "true", record_trace),
    ]:
        yield (
            f"arena payload {name}", record,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    yield (
        "indexed read accepts a different embedded name", record,
        lambda s: replace_once(s, "return Err(Error::Identifier);", "return Ok(record);"), record,
    )
    yield (
        "indexed read releases an unconfirmed record identity", record,
        lambda s: replace_once(s, "return Err(Error::Identity);", "return Ok(record);"), record,
    )
    yield (
        "indexed read loses the provenance of the identity failure", record,
        lambda s: replace_once(s, "actual@ != expected@ &&\n            body.ensures", "true &&\n            body.ensures"), record_trace,
    )
    yield (
        "indexed read parses the wrong body offset", record,
        lambda s: replace_once(s, "match body(payload,cursor)", "match body(payload,0)"), record,
    )
    yield (
        "arena reference reader omits the exact target bytes", record,
        lambda s: replace_once(s, "&&& id@ == bytes@.subrange(target+8,target+40)", "&&& true"), record,
    )
    yield (
        "arena reference list starts with the second entry", record,
        lambda s: replace_once(s, "let (label,id,kind) = match reference(bytes,cursor,scheme)", "let _ = reference(bytes,cursor,scheme);\n        let (label,id,kind) = match reference(bytes,cursor,scheme)"), record,
    )
    yield (
        "arena reference list loses its returned cursor", record,
        lambda s: replace_once(s, "v.len() == count && *final(cursor) as int == position(bytes@,*old(cursor) as int,count as nat) &&", "v.len() == count &&"), record_trace,
    )
    yield (
        "arena reference list forgets the packed record fields", record,
        lambda s: replace_once(s, "forall|i:nat| i < count ==> #[trigger] entry(bytes@,position(bytes@,*old(cursor) as int,i),scheme,pack,v@[i as int])", "true"), record_trace,
    )
    yield (
        "arena reference writer emits the wrong reachability code", record,
        lambda s: replace_once(s, "bytes.push(code);", "bytes.push(0);"), record,
    )
    walk = Path("crates/astrid-storage/src/engine/durable/closure_walk.rs")
    graph = Path("verification/hosted_closure_model.rs")
    yield (
        "closure walker accepts a cached root without checking its kind", walk,
        lambda s: replace_once(s, "source.check_root(root) {return", "(if cached.contains(&root) {Ok(())} else {source.check_root(root)}) {return"), walk,
    )
    yield (
        "closure walker drops the active cycle error", walk,
        lambda s: replace_once(s, "return Err(Failure::Cycle(id));", "continue;"), walk,
    )
    yield (
        "closure walker omits a newly loaded object from its result", walk,
        lambda s: replace_once(s, "marks.insert(id,Mark::Active);\n                        seen.insert(id);", "marks.insert(id,Mark::Active);"), walk,
    )
    yield (
        "closure scheduling substitutes the first edge for the selected edge", walk,
        lambda s: replace_once(s, "refs[pos].owned_target()", "refs[0].owned_target()"), walk,
    )
    yield (
        "closure completeness loses the source of an error", walk,
        lambda s: replace_once(s, "S::failed(old(source).edges(),k,e) && !cached@.contains(k)", "!cached@.contains(k)"), graph,
    )
    yield (
        "closure success forgets acyclicity", walk,
        lambda s: replace_once(s, "&&& exists|done:Map<K,nat>| done.dom() == seen@.difference(cached@) && #[trigger] ranked(old(source).edges(),cached@,done)", "&&& true"), graph,
    )
    yield (
        "closure validation forgets the inductive cache guarantee", walk,
        lambda s: replace_once(s, "&&& (certified(old(source).edges(),cached@) ==> certified(old(source).edges(),cached@.union(seen@)))",
                               "&&& true"), graph,
    )
    kind = Path("crates/astrid-storage/src/storage_model/reference_kind.rs")
    yield (
        "closure data classifies evidence as ownership", kind,
        lambda s: replace_once(s, "Self::Owns => Some(target),\n            Self::Evidence | Self::Lineage | Self::Derived => None",
                               "Self::Owns | Self::Evidence => Some(target),\n            Self::Lineage | Self::Derived => None"), kind,
    )
    yield (
        "closure wire decoder interprets lineage as ownership", kind,
        lambda s: replace_once(s, "2 => Some(Self::Lineage)", "2 => Some(Self::Owns)"), kind,
    )
    trace = Path("verification/hosted_wal_writer_trace.rs")
    yield (
        "paired owner recovery loses the applied map update", trace,
        lambda s: replace_once(s, "&&& final(history)@ == if out matches Some(Replay::Apply)", "&&& true || final(history)@ == if out matches Some(Replay::Apply)"), trace,
    )
    yield (
        "paired owner recovery loses successful generation admission", trace,
        lambda s: replace_once(s, "&&& out.is_some() == valid", "&&& true"), trace,
    )
    history = Path("crates/astrid-storage/src/engine/durable/wal/root_history.rs")
    yield (
        "WAL owner map drops the source offset", history,
        lambda s: replace_once(s, "history.insert(owner,(replacement,offset))", "history.insert(owner,(replacement,0))"), history,
    )
    yield (
        "WAL owner map publishes despite journal failure", history,
        lambda s: replace_once(s, "let journal = encode(&owner,expected,replacement)?;",
                               "let encoded = encode(&owner,expected,replacement);\n"
                               "            if encoded.is_err() {history.insert(owner,(replacement,offset)); return Err(encoded.err().unwrap());}\n"
                               "            let journal = encoded?;"), history,
    )
    yield (
        "WAL root history loses precision for unrelated owners", history,
        lambda s: replace_once(s, "history.insert(owner,(replacement,offset));", "history.clear(); history.insert(owner,(replacement,offset));"), history,
    )
    yield (
        "WAL publication forgets the encoded journal", history,
        lambda s: replace_once(s, "applicable && encode.ensures((&owner,expected,replacement),Ok(j))", "applicable"), trace,
    )
    yield (
        "released WAL root loses its body before owner recovery", trace,
        lambda source: replace_once(source, "&&& recovered@ == root_body@", "&&& true"), trace,
    )
    yield (
        "replay reads another owner's history", trace,
        lambda source: replace_once(source, "key_of(recovered)", "key_of(Owner::System)"), trace,
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
