"""Mutations that must fail in a downstream proof consumer."""

from pathlib import Path
from .common import (
    LEASE_CALLBACK,
    replace_once,
)


def consumer_defects():
    """Weaken a production guarantee and require its trace consumer to fail."""
    command = Path("crates/astrid-capsule/src/engine/wasm/host/process/command.rs")
    for name, original, changed, target in [
        ("skips the environment clear", "    builder.clear_environment();", "", command),
        ("drops argv", "    builder.arguments(args);", "", command),
        ("substitutes an environment value", "pair.1.as_str()", "pair.0.as_str()", command),
        ("replays the request after injections", "apply_environment(&mut builder, injections);",
         "apply_environment(&mut builder, environment);", command),
        ("loses host precedence", "Step::Directory(cwd), Step::Clear] + assignments(environment) + assignments(injections),",
         "Step::Directory(cwd), Step::Clear] + assignments(environment) + assignments(injections) || true,",
         Path("verification/hosted_process_command.rs")),
    ]:
        yield (
            f"process construction {name}", command,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    reply = Path("crates/astrid-capsule/src/engine/wasm/host/consent_reply.rs")
    trace = Path("verification/hosted_consent_reply.rs")
    for name, original, changed, target in [
        ("loses retirement rejection", "Err(()) => held.is_none(),\n        Ok(p)", "Err(()) => true,\n        Ok(p)", trace),
        ("loses caller retirement rejection", "Err(()) => held.is_none(),\n            Ok(c)", "Err(()) => true,\n            Ok(c)", trace),
        ("loses responder retirement rejection", "Err(()) => held.is_none(),\n            },", "Err(()) => true,\n            },", trace),
        ("drops live device admission", "held matches Some(h) && h.guards() == (p,c,s)", "true", trace),
        ("grants unknown decisions", "else {Decision::Deny}\n}\n\n/// Hosted", "else {Decision::Once}\n}\n\n/// Hosted", reply),
        ("skips persistent publication", "save_at(p,a,destination,writer)?;", "let _ = destination;", reply),
        ("reports the wrong scope", "Ok(decision)\n}", "Ok(Decision::Always)\n}", reply),
        ("loses persistent acknowledgement", "value == Decision::Always && old(writer).permits(p,a,d,Ok(()))", "value == Decision::Always", trace),
        ("loses the persistence error", "Err(error) => old(writer).permits(p,a,d,Err(error))", "Err(error) => true", trace),
        ("writes both workspace scopes", "Destination::Hosted(path) => writer.hosted(p,a,path)", "Destination::Hosted(path) => {let _ = writer.workspace(p,a); writer.hosted(p,a,path)}", reply),
        ("misroutes a hosted write", "Destination::Hosted(path) => writer.hosted(p,a,path)", "Destination::Hosted(path) => writer.workspace(p,a)", reply),
        ("writes after a nonpersistent reply", "save_at(p,a,destination,writer)?;\n    }", "save_at(p,a,destination,writer)?;\n    } else if let Ok(d) = target {let _ = save_at(p,a,d,writer);}", reply),
        ("loses the exclusive write history", "final(writer).attempts() == match target {", "true || final(writer).attempts() == match target {", trace),
        ("suppresses an unusable destination", "Err(e) => out == Err(e)", "Err(e) => true", trace),
    ]:
        yield (
            f"approval reply {name}", reply,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    registration = Path("crates/astrid-core/src/profile/device_registration.rs")
    profile_trace = Path("verification/hosted_device_profile.rs")
    for name, original, changed in [
        ("omits enabled profile policy", "Some(record) => enabled && keypair &&", "Some(record) => keypair &&"),
        ("forgets the selected generation", "&& generation.ensures((record,),expected)", ""),
        ("forgets the selected record", "&& *record == rows@[i],", ","),
        ("permits rejection of a live record", "None => !enabled || !keypair", "None => true || !enabled || !keypair"),
    ]:
        yield (
            f"device profile {name}", registration,
            lambda s, a=original, b=changed: replace_once(s, a, b), profile_trace,
        )
    for name, original, changed, expected_file in [
        ("loses signed lookup rejection", "ensures r.is_ok() == self.permitted()", "ensures true", trace),
        ("ignores a retiring registry", "&& bind_after_lookup(Vec::new(),0,self.principal,self.fingerprint,self.retirement) { Ok(self.generation)", "{ Ok(self.generation)", profile_trace),
    ]:
        yield (
            f"device profile {name}", profile_trace,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            expected_file,
        )
    for name, original, changed, source, expected_file in [
        ("ignores rejected principal admission", "wire,owner_guard,caller.admission()", "wire,Ok(()),caller.admission()", trace, trace),
        ("retires an unrelated owner", "entries.as_mut_slice(),who,which", "entries.as_mut_slice(),key,which", profile_trace, profile_trace),
        ("ignores the observed retirement", "self.fingerprint,self.retirement) { Ok(self.generation)", "self.fingerprint,None) { Ok(self.generation)", profile_trace, profile_trace),
    ]:
        yield (
            f"approval registry {name}", source,
            lambda s, a=original, b=changed: replace_once(s, a, b), expected_file,
        )
    copies = Path("crates/astrid-storage/src/engine/durable/format/duplicates.rs")
    copies_trace = Path("verification/hosted_duplicate_recovery.rs")
    for name, original, changed, target in [
        ("accepts different bytes", "if original.as_slice() != copy.as_slice()", "if false", copies),
        ("reads beyond the gap", "arena.bounded(cursor,end)", "arena.bounded(cursor,u64::MAX)", copies),
        ("reads original at the duplicate offset", "arena.bounded(first.offset,cursor)", "arena.bounded(cursor,end)", copies),
        ("ignores indexed payload length", " || first.payload_len != length", "", copies),
        ("advances by the payload only", "cursor.checked_add(52)", "cursor.checked_add(0)", copies),
        ("rejects complete duplicate runs", "    true\n}", "    false\n}", copies),
        ("forgets successful coverage", "ok ==> tiled(old(arena).frames(),map@,scheme,start,end)", "ok ==> true", copies_trace),
        ("forgets reliable admission", "old(arena).dependable() && tiled(old(arena).frames(),map@,scheme,start,end) ==> ok", "false ==> ok", copies_trace),
    ]:
        yield (
            f"arena duplicate {name}", copies,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    walk_source = Path("crates/astrid-storage/src/engine/durable/closure_walk.rs")
    yield (
        "closure diagnostic loses the cycle through its reported object", walk_source,
        lambda s: replace_once(s, "&& reaches(old(source).edges(),cached@,k,k) &&", "&& true &&"),
        Path("verification/hosted_closure_model.rs"),
    )
    record = Path("crates/astrid-storage/src/engine/durable/format/verified_record.rs")
    record_trace = Path("verification/hosted_record_model.rs")
    arena = Path("crates/astrid-storage/src/engine/durable/format/arena_span.rs")
    for name, clause, weaker, target in [
        ("shifts the physical frame", "offset.checked_sub(start)?", "offset.checked_sub(start)?.checked_add(1)?", arena),
        ("ignores the frame checksum", "sum.as_slice() != &bytes[20..52] || ", "", arena),
        ("forgets the addressed payload", "Ok(p) => p@ == bytes@.skip(52)", "Ok(p) => true", record_trace),
        ("forgets the read offset", "read.ensures((offset,),Ok((data,checksum)))", "true", record_trace),
        ("allows rejection of a matching placement", "(data.len() != size || sum != checksum) &&", "true &&", record_trace),
    ]:
        yield (
            f"indexed arena {name}", arena,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )
    positional = Path("crates/astrid-storage/src/engine/durable/format/positional_read.rs")
    for name, clause, weaker, target in [
        ("restarts a short read at the initial offset", "media.read_at(position,part)", "media.read_at(offset,part)", positional),
        ("forgets the stable media interval", "final(buffer)@ == media.image().subrange(offset as int,offset as int + final(buffer).len())", "true", record_trace),
    ]:
        yield (
            f"indexed arena {name}", positional,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )
    yield (
        "indexed arena loses the decoded record identity", record,
        lambda s: replace_once(s, "record_at(frame@,40,scheme,r) &&\n            (exists|digest:[u8;32]| digest@ == id.digest() && #[trigger] identify.ensures((&r,),digest))",
            "record_at(frame@,40,scheme,r)"), record_trace,
    )
    placement_trace = Path("verification/hosted_arena_placement.rs")
    index = Path("crates/astrid-storage/src/engine/durable/arena_index.rs")
    placement = Path("crates/astrid-storage/src/engine/durable/direct_placement.rs")
    for name, source, clause, change, target in [
        ("assigns the next index slot", index, "publish(index,delta,keys[i],locations[i]);", "publish(index,delta,keys[i],locations[0]);", index),
        ("loses the lookup key", index, "location == index@[key] &&", "true &&", placement_trace),
        ("loses the description key", index, "*d == direct@[key]", "true", placement_trace),
        ("publishes the first direct location repeatedly", placement, "install(direct,description,locations[i]);", "install(direct,description,locations[0]);", placement),
        ("loses the index updates", placement, "final(index)@ == super::arena_index::applied(old(index)@,ids@,locations@,ids@.len())", "true", placement_trace),
        ("loses the checkpoint delta", placement, "final(delta)@ == old(delta)@ + Seq::new(ids@.len(),|i:int| (ids@[i],locations@[i]))", "true", placement_trace),
        ("loses catalogue updates", placement, "final(direct)@ == catalogue(old(direct)@,descriptions@,locations@,ids@.len())", "true", placement_trace),
        ("loses the profile-bound blob", placement, "identify.ensures((profile,bytes),Ok(prepared.fields().1))", "true", placement_trace),
        ("loses the canonical body", record, "body@ == bytes@.skip(40)", "true", placement_trace),
    ]:
        yield (
            f"arena staging {name}", source,
            lambda s, a=clause, b=change: replace_once(s, a, b), target,
        )
    overlay = Path("crates/astrid-storage/src/engine/durable/wal/overlay_object.rs")
    append = Path("crates/astrid-storage/src/engine/durable/arena_frame.rs")
    vectors = Path("crates/astrid-storage/src/engine/durable/arena_vectors.rs")
    readback = Path("verification/hosted_arena_append.rs")
    for name, source, original, changed, target in [
        ("omits the frame header width", append, "offset.checked_add(WIDTH as u64)?.checked_add(size)?", "offset.checked_add(size)?", append),
        ("reverses a vector pair", vectors, "parts.push(P::borrow(header));\n        parts.push(P::borrow(payload));", "parts.push(P::borrow(payload));\n        parts.push(P::borrow(header));", vectors),
        ("advances past an unwritten byte", vectors, "cursor.advance(n);", "cursor.advance(n.saturating_add(1));", vectors),
        ("loses the prepared checksum binding", append, "hashed(hash,magic,payload@,f.sum()),", "true,", readback),
        ("forgets the published offset", append, "loc.offset as int == base as int + prefix(frames@,i as nat).len()", "true", readback),
        ("forgets the returned checksum", append, "loc.checksum == frames@[i].sum()", "true", readback),
        ("forgets submitted bytes", append, "&&& final(sink).sent() == old(sink).sent() + bytes", "&&& true", readback),
        ("allows spurious sink failure", append, "failed_chunk::<S>(old(sink).sent(),frames@,batch_size,e) &&", "true &&", readback),
        ("loses the prefix on a failed batch", append, "exists|n:int| 0 <= n <= bytes.len() && final(sink).sent() == old(sink).sent() + bytes.take(n),", "true,", readback),
        ("drops vector ordering", vectors, "flatten(parts@,parts@.len()) == prefix(batch@,batch@.len()),", "true,", readback),
        ("loses completion of short writes", vectors, "out.is_ok() ==> final(cursor).sent() == old(cursor).sent()+old(cursor).remaining()", "true", readback),
        ("overwrites the first WAL object on equal bytes", overlay, "if before != after {return Err(());}", "if before != after {return Err(());} self.record = incoming.record;", overlay),
    ]:
        yield (
            f"arena append {name}", source,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    checkpoint_key = Path("crates/astrid-storage/src/engine/durable/index/key.rs")
    for name, source, original, changed, target in [
        ("encodes offset in the length field", append, "little_endian(self.payload_len)", "little_endian(self.offset)", append),
        ("reads the checksum one byte early", append, "checksum.copy_from_slice(&bytes[16..]);", "checksum.copy_from_slice(&bytes[15..47]);", append),
        ("loses successful decode bytes", append, "loc.wire() == bytes@,", "true,", checkpoint_key),
        ("forgets the encoded placement", append, "final(bytes)@ == old(bytes)@ + self.wire(),", "true,", readback),
        ("drops the header from the restored endpoint", append, "self.offset.checked_add(WIDTH as u64)?.checked_add(self.payload_len)", "self.offset.checked_add(self.payload_len)", append),
        ("loses the endpoint relation", append, "(end matches Some(value) ==> value == e)", "true", readback),
        ("accepts a conflicting restored identity", index, "previous.offset != loc.offset ||", "false ||", index),
        ("forgets the replayed map", index, "final(index)@ == if accepted {old(index)@.insert(key,loc)} else {old(index)@},", "true,", readback),
    ]:
        yield (
            f"checkpoint placement {name}", source,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    for name, original, changed, target in [
        ("uses the wrong digest", "Ok(ObjectId::new(id))", "Ok(ObjectId::new([0;32]))", checkpoint_key),
        ("ignores the construction", "construction.as_slice() != expected.construction.as_slice()", "false", checkpoint_key),
        ("accepts a repeated key", "Some(prior) => prior.strictly_before(&id)", "Some(prior) => true", checkpoint_key),
        ("loses the decoded row identity", "&& id.digest() == bytes@.subrange(start+8,start+40)", "&& true", readback),
        ("loses the selected location bytes", "&&& loc.wire() == bytes@.subrange(start+40,start+88)", "&&& true", readback),
        ("drops recovered map provenance", "mapped(bytes@,*old(cursor) as int,count as nat,map@) &&", "true &&", readback),
        ("drops table ordering", "(forall|i:int| 0 <= i < count ==> #[trigger] ordered_row(bytes@,*old(cursor) as int,i,scheme)),", "true,", readback),
    ]:
        yield (
            f"checkpoint keys {name}", checkpoint_key,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
    yield (
        "checkpoint keys permit spurious table lookup failure", readback,
        lambda s: replace_once(s, "out.is_some() == (forall|i:int| 0 <= i < count",
            "out.is_some() ==> (forall|i:int| 0 <= i < count"), readback,
    )
    recovery = Path("verification/hosted_checkpoint_recovery.rs")
    admission = Path("crates/astrid-storage/src/engine/durable/index/admission.rs")
    rebuild = Path("crates/astrid-storage/src/engine/durable/index/rebuild.rs")
    image = Path("crates/astrid-storage/src/engine/durable/format/checkpoint_reader.rs")
    for name, source, original, changed, target in [
        ("checks a different frame offset", image, "media.seek(loc.offset)", "media.seek(0)", image),
        ("ignores the embedded identity", image, "if digest.as_slice() != expected.as_bytes().as_slice()", "if false", image),
        ("reads beyond a short frame", image, "if declared < 40", "if declared < 39", image),
        ("loses short-frame cursor provenance", image, "loc.payload_len < 40 && final(media).position() == loc.offset as int+52,", "loc.payload_len < 40,", recovery),
        ("loses the successful image relation", image, "out.is_ok() ==> matches(old(media).image(),magic,version,loc,scheme,expected,limit) &&", "out.is_ok() ==> true &&", recovery),
        ("changes a physical mapping", admission, "items.push((*id,*loc));", "items.push((*id,ArenaLocation {offset:0,..*loc}));", admission),
        ("checks the first row repeatedly", admission, "let (id,loc) = rows[i];", "let (id,loc) = rows[0];", admission),
        ("admits a failed checkpoint scan", admission, "if !complete {return None;}", "if !complete && measured == 0 {return None;}", admission),
        ("accepts stale coverage", admission, "if covered != measured {return false;}", "if covered < measured {return false;}", admission),
        ("skips tail verification", admission, "Some(loc) => arena.tail(loc)", "Some(loc) => true", admission),
        ("drops admission provenance", admission, "complete && candidate == Some(s) &&\n                consistent(s.objects@,s.arena_tail,s.arena_len,measured,old(arena).entries(),old(arena).tails())", "complete && candidate == Some(s)", recovery),
        ("skips a physical gap", admission, "if loc.offset != end && !arena.gap(map,end,loc.offset)", "if loc.offset < end && !arena.gap(map,end,loc.offset)", admission),
        ("drops the final frame extent", admission, "if end != measured && !arena.gap(map,end,measured)", "if end > measured && !arena.gap(map,end,measured)", admission),
        ("advances past the declared frame", admission, "end = next;", "end = next.saturating_add(1);", admission),
        ("loses the accepted physical partition", admission, " && covered_with(s.objects@,measured,old(arena).gaps(s.objects@)),", ",", recovery),
        ("loses accepted cache identity", rebuild, "Some(s) => out == Ok(s),", "Some(s) => true,", recovery),
        ("loses completed replacement", rebuild, "exists|value:&T,r:Result<(),E>| *value == s && r.is_ok() && #[trigger] publish.ensures((value,),r)", "true", recovery),
    ]:
        yield (
            f"checkpoint recovery {name}", source,
            lambda s, a=original, b=changed: replace_once(s, a, b), target,
        )
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
