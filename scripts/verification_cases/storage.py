"""Implementation mutations for storage verification."""

from pathlib import Path
from .common import (
    BINDING,
    GUEST_AUTHORITY,
    KV_ENCODING,
    OVERLAY,
    OVERLAY_UPDATE,
    edit_function,
    replace_once,
)


def defects():
    stream = Path("verification/hosted_wal_stream.rs")
    buffer = Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs")
    return [
        (
            "file reader repeats the first destination after a short read",
            buffer,
            lambda source: replace_once(source, "destination[filled..]", "destination[..]"),
        ),
        (
            "file reader treats the first fragment as the entire buffer",
            buffer,
            lambda source: replace_once(source, "filled = filled.saturating_add(n);", "return Ok(n);"),
        ),
        (
            "file reader accepts a missing payload suffix",
            buffer,
            lambda source: replace_once(source, "return Ok(Payload::Short)", "return Ok(Payload::Complete)"),
        ),
        (
            "file reader restores the file length instead of the payload cursor",
            buffer,
            lambda source: replace_once(source, "source.seek_start(restore)", "source.seek_start(length)"),
        ),
        (
            "file reader accepts a failed cursor restoration",
            buffer,
            lambda source: replace_once(source, "Err(e)=>Err(LengthError::Restore(e))", "Err(_)=>Ok(length)"),
        ),
        (
            "stream scan releases the batch against the Commit offset",
            stream,
            lambda source: replace_once(source, "Event::Commit {offset:start as u64,marker:checked}", "Event::Commit {offset:cursor as u64,marker:checked}"),
        ),
        (
            "stream scan swaps a root span for the Begin span",
            stream,
            lambda source: replace_once(source, "DataKind::Root => Event::Root(r)", "DataKind::Root => Event::Root(begin)"),
        ),
        (
            "stream scan restarts at Begin instead of advancing",
            stream,
            lambda source: replace_once(source, "read_record(stream,cursor,limit,chunk_size,hash,checksum,Ghost(hint))", "read_record(stream,start,limit,chunk_size,hash,checksum,Ghost(hint))"),
        ),
        (
            "stream scan refuses every completed transaction",
            stream,
            lambda source: replace_once(source, "return Some(Scan {end:r.next,marker:checked,batch,trace:Ghost((rs,r))});", "return None;"),
        ),
        (
            "stream scan returns the start of Commit as the next cursor",
            stream,
            lambda source: replace_once(source, "Scan {end:r.next,marker:checked", "Scan {end:cursor,marker:checked"),
        ),
        (
            "stream scan digests only the last stored record",
            stream,
            lambda source: replace_once(source, "data.extend_from_slice(&part);", "data = part;"),
        ),
        (
            "stream scan admits objects after a root",
            stream,
            lambda source: replace_once(source, "if counts.roots != 0 { return None; }", ""),
        ),
        (
            "Commit frame takes its ordinal from the root count",
            Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
            lambda source: replace_once(source, "ordinal:little_endian(self.counts.logical)", "ordinal:little_endian(self.counts.roots)"),
        ),
        (
            "Commit frame sets a nonzero physical feature flag",
            Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
            lambda source: replace_once(source, "seal(frame.as_mut_slice(),0,hash)", "seal(frame.as_mut_slice(),1,hash)"),
        ),
        (
            "Commit reader skips the transaction root requirement",
            Path("verification/hosted_wal_model.rs"),
            lambda source: replace_once(source, " || observed.roots == 0 { return None; }", " { return None; }"),
        ),
        (
            "measured WAL reader ignores the supplied frame offset",
            Path("verification/hosted_wal_binding.rs"),
            lambda source: replace_once(source, "read_at(&stream,prefix.len(),limit,hash,checksum,usize::MAX)", "read_at(&stream,0,limit,hash,checksum,usize::MAX)"),
        ),
        (
            "measured WAL reader ignores the supplied payload limit",
            Path("verification/hosted_wal_binding.rs"),
            lambda source: replace_once(source, "read_at(&stream,prefix.len(),limit,hash,checksum,usize::MAX)", "read_at(&stream,prefix.len(),u64::MAX,hash,checksum,usize::MAX)"),
        ),
        (
            "measured WAL object parser accepts an unknown storage flag",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "1 => Some(Self::Lz4), _ => None", "1 => Some(Self::Lz4), _ => Some(Self::Plain)"),
        ),
        (
            "measured WAL physical features admit flagged roots",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "2 => matches!(kind,WalRecordKind::Object) && flags == 1", "2 => flags == 1"),
        ),
        (
            "measured WAL physical frame drops the checksum tail",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "header[20..].copy_from_slice(&self.checksum);", "header[20..51].copy_from_slice(&self.checksum[..31]);"),
        ),
        (
            "measured WAL oversized record masks an incomplete span",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "if end > file {Extent::Incomplete} else if size > limit {Extent::Oversized}", "if size > limit {Extent::Oversized} else if end > file {Extent::Incomplete}"),
        ),
        (
            "measured WAL writer frames the next ordinal",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "ordinal:little_endian(self.ordinal)", "ordinal:little_endian(self.counts.logical)"),
        ),
        (
            "measured WAL writer omits the stored payload",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "header.append(&mut frame,self.body);", "header.append(&mut frame,&[]);"),
        ),
        (
            "measured WAL observer drops object flags",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "digest_record(self.kind,self.flags,self.counts.sequence", "digest_record(self.kind,0,self.counts.sequence"),
        ),
        (
            "measured WAL root is classified as an object",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "(Entry::Root,WalRecordKind::Root,0)", "(Entry::Root,WalRecordKind::Object,0)"),
        ),
        (
            "measured WAL begin skips ordinal zero",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "flags:0,ordinal:0,counts,body", "flags:0,ordinal:1,counts,body"),
        ),
        (
            "measured WAL writer drops the declared seal",
            Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
            lambda source: replace_once(source, "let bytes = self.encode(frame,hash)?;", "let bytes = frame;"),
        ),
        (
            "publication accepts a mismatched forward binding",
            BINDING,
            lambda text: replace_once(text, "f.as_slice() != uid.as_slice() || ", ""),
        ),
        (
            "publication accepts a mismatched reverse binding",
            BINDING,
            lambda text: replace_once(text, " || r != alias", ""),
        ),
        (
            "WAL physical header accepts unknown versions",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "|| !(header[8] == 1 || header[8] == 2)", "|| header[8] == 0"),
        ),
        (
            "WAL physical checksum compares a prefix",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "sum.as_slice() != self.checksum.as_slice()", "sum[..16] != self.checksum[..16]"),
        ),
        (
            "WAL physical seal writes a legacy version for compressed data",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "let header = Envelope { version:if flags == 0 {1} else {2}", "let header = Envelope { version:if flags == 0 {1} else {1}"),
        ),
        (
            "WAL physical exact fit is discarded",
            Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
            lambda source: replace_once(source, "if end > file {", "if end >= file {"),
        ),
        (
            "WAL physical scan skips an interior offset",
            Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
            lambda source: replace_once(source, "at.saturating_add(1)", "at.saturating_add(2)"),
        ),
        (
            "WAL physical tail resumes within the active transaction",
            Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
            lambda source: replace_once(source, "Some(begin) => Boundary::Tail(begin),\n        None if damaged", "Some(_) => Boundary::Tail(cursor),\n        None if damaged"),
        ),
        (
            "WAL physical probe loses its I/O error",
            Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
            lambda source: replace_once(source, "return (reader,Err((at,error)));", "return (reader,Ok(None));"),
        ),
        (
            "WAL measurement counts the wrong stored length",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "(HEADER_LEN as u64).checked_add(body.len() as u64)", "(HEADER_LEN as u64).checked_add(0)"),
        ),
        (
            "WAL measurement drops the Begin record",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "sequence, logical: 1, objects: 0", "sequence, logical: 0, objects: 0"),
        ),
        (
            "WAL measurement increments the wrong object counter",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "next.objects = before.objects.checked_add", "next.roots = before.objects.checked_add"),
        ),
        (
            "WAL measurement advances ordinal twice",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "next.logical = before.logical.checked_add(1)", "next.logical = before.logical.checked_add(2)"),
        ),
        (
            "WAL measurement digest drops the object flags",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "header[2] = flags;", "header[2] = 0;"),
        ),
        (
            "WAL measurement digest swaps ordinal and sequence",
            Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
            lambda source: replace_once(source, "little_endian(ordinal)", "little_endian(sequence)"),
        ),
        (
            "stale KV view falls back to neutral and completes the request",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(source, "Some(uid) => Some(Destination::Principal(uid)),\n                None => None,", "Some(uid) => Some(Destination::Principal(uid)),\n                None => Some(Destination::Neutral),"),
        ),
        (
            "WAL Commit wire writes an object count in the root count slot",
            Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
            lambda source: replace_once(source, "body[24..32].copy_from_slice(&little_endian(self.counts.roots));",
                                       "body[24..32].copy_from_slice(&little_endian(self.counts.objects));"),
        ),
        (
            "WAL Commit validator accepts a different byte count",
            Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
            lambda source: replace_once(source, "if self.bytes != observed.bytes", "if self.bytes < observed.bytes"),
        ),
        (
            "WAL Commit validator authenticates its own stored digest",
            Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
            lambda source: replace_once(source, "if !self.digest_matches(&digest)", "if !self.digest_matches(&self.digest)"),
        ),
        (
            "WAL replay commits descriptors from another begin offset",
            Path("crates/astrid-storage/src/engine/durable/wal/transaction.rs"),
            lambda source: replace_once(source, " || batch.origin.offset != offset", ""),
        ),
        (
            "WAL replay releases descriptors at an uncommitted tail",
            Path("crates/astrid-storage/src/engine/durable/wal/transaction.rs"),
            lambda source: replace_once(source, "Event::Tail => Ok(Step::End),",
                                       "Event::Tail => match pending { Some(b) => Ok(Step::Committed(b)), None => Ok(Step::End) },"),
        ),
        (
            "WAL record header repeats the sequence in the ordinal field",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "encoded.extend_from_slice(&self.ordinal);", "encoded.extend_from_slice(&self.sequence);"),
        ),
        (
            "WAL scanner skips the first logical body byte",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "let body = &payload[HEADER_LEN..];", "let body = &payload[HEADER_LEN.saturating_add(1).min(payload.len())..];"),
        ),
        (
            "WAL dispatch accepts a record with an old ordinal",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "if ordinal != expected_ordinal", "if ordinal > expected_ordinal"),
        ),
        (
            "WAL writer binds a different prepared replacement",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "!equal_root(replacement,next)", "!equal_root(replacement,replacement)"),
        ),
        (
            "WAL sync failure leaves the writer usable",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "*poisoned = true;", "*poisoned = false;"),
        ),
        (
            "successful WAL sync acknowledges an empty group",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ok(count)", "Ok(0)"),
        ),
        (
            "WAL frontier rewinds to a shorter arena",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ordering::Less => None", "Ordering::Less => Some((observed, tail))"),
        ),
        (
            "unchanged WAL frontier replaces the published tail",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ordering::Equal => Some((current, tail))", "Ordering::Equal => Some((current, pending))"),
        ),
        (
            "transition journals record the construction in place of the algorithm",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "bytes.extend_from_slice(&scheme.algorithm);", "bytes.extend_from_slice(&scheme.construction);"),
        ),
        (
            "root payload reader skips the last byte of a field",
            Path("crates/astrid-storage/src/storage_fields.rs"),
            lambda source: replace_once(source, "*cursor = end;", "*cursor = end.saturating_sub(1);"),
        ),
        (
            "WAL transition accepts trailing bytes",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "if *cursor != bytes.len()", "if *cursor > bytes.len()"),
        ),
        (
            "durable principal encoded as fleet",
            Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
            lambda source: replace_once(source, "Self::Principal(id) => (1u8, id)", "Self::Principal(id) => (2u8, id)"),
        ),
        (
            "owner recovery substitutes the first UID byte",
            Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
            lambda source: replace_once(source, "id[i] = bytes[i.saturating_add(1)]", "id[i] = bytes[1]"),
        ),
        (
            "prepared root encodes a different expected root",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "encode(&owner,expected,replacement)?", "encode(&owner,None,replacement)?"),
        ),
        (
            "WAL staging discards prepared journal bytes",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "write(&self.owner,self.expected,self.replacement,&self.journal)", "write(&self.owner,self.expected,self.replacement,&Vec::new())"),
        ),
        (
            "durable root admission ignores the commit digest",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, " || a.commit.as_slice() != b.commit.as_slice()", ""),
        ),
        (
            "durable root admission accepts a mismatched generation",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "a.generation != b.generation || ", ""),
        ),
        (
            "WAL replay publishes an already committed replacement",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "{ Replay::AlreadyPublished }", "{ Replay::Apply }"),
        ),
        (
            "guest KV releases admission before invoking the sink",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(
                replace_once(source, "    tracker.finish();", ""),
                "if !tracker.begin() { return None; }",
                "if !tracker.begin() { return None; } tracker.finish();",
            ),
        ),
        (
            "KV completion fails to release its acquired owner count",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(source, "    tracker.finish();", ""),
        ),
        (
            "stale install ownership follows a reassigned alias",
            BINDING,
            lambda text: replace_once(text, "uid.as_slice() != observed.as_slice() => None",
                                      "uid.as_slice() != observed.as_slice() => Some(observed)"),
        ),
        (
            "ordered overlay replacement retains its old value",
            OVERLAY_UPDATE,
            lambda text: replace_once(text, "make_node(entry, node.left.clone(), node.right.clone())",
                                      "make_node(Arc::clone(&node.entry), node.left.clone(), node.right.clone())"),
        ),
        (
            "left rotation drops the inner subtree",
            OVERLAY_UPDATE,
            lambda text: edit_function(text, "rotate_left", "right.left.clone()", "None"),
        ),
        (
            "right rotation drops the inner subtree",
            OVERLAY_UPDATE,
            lambda text: edit_function(text, "rotate_right", "left.right.clone()", "None"),
        ),
        (
            "overlay drops an exact key including its tombstone",
            OVERLAY,
            lambda text: replace_once(text, "Ordering::Equal => return Some(&node.entry.value)", "Ordering::Equal => return None"),
        ),
        (
            "overlay searches the wrong subtree",
            OVERLAY,
            lambda text: replace_once(text, "Ordering::Less => node.left.as_ref()", "Ordering::Less => node.right.as_ref()"),
        ),
        (
            "checkpoint leaf ignores the lower fence",
            KV_ENCODING,
            lambda text: replace_once(text, "!bytewise_less(key, start) && bytewise_less(key, end)", "bytewise_less(key, end)"),
        ),
        (
            "checkpoint traversal skips the last child",
            KV_ENCODING,
            lambda text: replace_once(text, "_ => bytewise_less(lower, end),", "None => false, _ => bytewise_less(lower, end),"),
        ),
        (
            "byte order reverses strict-prefix ties",
            KV_ENCODING,
            lambda text: edit_function(text, "bytewise_cmp", "left.len().cmp(&right.len())", "right.len().cmp(&left.len())"),
        ),
        (
            "prefix range includes sibling namespaces",
            KV_ENCODING,
            lambda text: edit_function(
                text, "logical_prefix_range", "== (ns == other && matches_prefix(key, prefix))",
                "== matches_prefix(key, prefix)",
            ),
        ),
        (
            "prefix range excludes the exact prefix",
            KV_ENCODING,
            lambda text: replace_once(text, "end[pivot] = byte.saturating_add(1);", "end[pivot] = byte;"),
        ),
        (
            "prefix interval ignores its lower bound",
            KV_ENCODING,
            lambda text: edit_function(
                text, "prefix_interval", "(!below(key, start) && below(key, end))", "below(key, end)"
            ),
        ),
        (
            "physical entry drops the requested key",
            KV_ENCODING,
            lambda text: replace_once(text, "address.extend_from_slice(key);", ""),
        ),
        (
            "physical address loses namespace separation",
            KV_ENCODING,
            lambda text: replace_once(text, "address.push(0);", ""),
        ),
        (
            "guest namespace can follow a replacement owner",
            GUEST_AUTHORITY,
            lambda text: replace_once(text, " && same_bytes(pinned.as_slice(), observed.as_slice())", ""),
        ),
        (
            "guest owner can access a sibling namespace",
            GUEST_AUTHORITY,
            lambda text: replace_once(text, "same_bytes(admitted, requested) && ", ""),
        ),
    ]


def group_root_consumer_defects():
    for name, old, new in [
        ("staging can overwrite another owner", "final(pending)@ == old(pending)@.insert(self.binding().0,self.binding().2)", "final(pending)@.contains_key(self.binding().0)"),
        (
            "stale and exhausted roots can report the wrong refusal",
            "(out.1 is Conflict) == (out.0 != expected),\n"
            "        (out.1 is Overflow) == (out.0 == expected && (expected matches Some(r) && r.generation.value() == u64::MAX)),",
            "true,",
        ),
        ("success may skip a generation", "n as int == r.generation.value() as int + 1", "n as int > r.generation.value() as int"),
        (
            "lookup can return an unrelated version",
            "ensures out.0 == if pending@.contains_key(*owner) {Some(pending@[*owner])}\n"
            "        else if published@.contains_key(*owner) {Some(published@[*owner])} else {None},",
            "ensures out.0.is_some() == (pending@.contains_key(*owner) || published@.contains_key(*owner)),",
        ),
    ]:
        yield (
            f"group root {name}", Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source, a=old, b=new: replace_once(source, a, b),
            Path("verification/hosted_wal_writer_trace.rs"),
        )


def key_projection_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/key_projection.rs")
    consumer = Path("verification/hosted_key_projection.rs")
    for label, clause, weaker in [
        ("checkpoint insertion", "final(map).deep_view() == old(map).deep_view().insert(key.deep_view(),true)", "true"),
        ("overlay replacement", "final(map).deep_view() == old(map).deep_view().insert(key.deep_view(),value.is_some())", "true"),
        ("visible keys", "&& (forall|k:K| #[trigger] seen.contains(k) == (keys@.get(k) == Some(true)))", "&& (forall|k:K| #[trigger] seen.contains(k) ==> (keys@.get(k) == Some(true)))"),
        ("projected value", "&& (forall|i:int| 0 <= i < seen.len() ==> #[trigger] project.ensures((&seen[i],),Ok(out@[i])))", ""),
        ("namespace suffix", "out matches Some(bytes) ==> bytes@ == key@.skip(strip as int)", "true"),
    ]:
        yield (
            f"KV key projection loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def overlay_range_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/overlay/range.rs")
    consumer = Path("verification/hosted_overlay_range.rs")
    for label, clause, weaker in [
        ("initial snapshot", "out.remaining() == rows(deref_option(root),start@,end@)", "true"),
        ("yielded entry", "result == Some(&*old(self).remaining()[0])", "result.is_some()"),
        ("remaining tail", "final(self).remaining() == old(self).remaining().drop_first()", "final(self).remaining().len() + 1 == old(self).remaining().len()"),
        ("half-open membership", "== (contains_entry(root,key,value) && encoding::range_contains(start,end,key))",
         "==> (contains_entry(root,key,value) && encoding::range_contains(start,end,key))"),
        ("applied presence", "final(keys).deep_view() ==\n        fold(old(keys).deep_view(),rows(deref_option(root),start@,end@))", "true"),
    ]:
        yield (
            f"overlay range loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_range_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_range.rs")
    consumer = Path("verification/hosted_checkpoint_range.rs")
    for label, clause, weaker in [
        ("summary equality", "ensures ok == (self.object == *object", "ensures ok ==> (self.object == *object"),
        ("authenticated object", "ensures id == match self", "ensures false ==> id == match self"),
        ("scheduled pointers", "final(stack)@ == old(stack)@ + scheduled(input@,0,start@,end@)", "true"),
        ("covering child", "if selected(children,i as int,start,end) { tail.push", "if false && selected(children,i as int,start,end) { tail.push"),
        ("pop order", "tail.push(Page::Child(children[i as int]))", "seq![Page::Child(children[i as int])] + tail"),
    ]:
        yield (
            f"checkpoint range loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_leaf_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf.rs")
    consumer = Path("verification/hosted_checkpoint_leaf.rs")
    for label, clause, weaker in [
        ("native presence update", "after.deep_view() == keys.deep_view().insert(entry.key@,true)", "true"),
        ("infallible presence callback", "Err(_) => false,", "Err(_) => true,"),
        ("completed prefix", "Ok(s) => visited(rows@,rows@.len(),start@,end@,initial,s,callback)", "Ok(_) => true"),
        ("earlier deliveries", "Err(e) => exists|i:int,s:S| 0 <= i < rows.len() &&\n            visited(rows@,i as nat,start@,end@,initial,s,callback) &&", "Err(e) => exists|i:int,s:S| 0 <= i < rows.len() &&"),
        ("rejected range", "encoding::range_contains(start@,end@,rows@[i].key@) &&", "true &&"),
        ("original failure", "#[trigger] callback.ensures((s,rows@[i]),Err(e)),",
         "(#[trigger] callback.requires((s,rows@[i])) || callback.ensures((s,rows@[i]),Err(e))),"),
    ]:
        yield (
            f"checkpoint leaf loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_walk_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_walk.rs")
    consumer = Path("verification/hosted_checkpoint_walk.rs")
    for label, clause, weaker in [
        ("starting root", "all[0] == (initial(root),first)", "true"),
        ("leaf delivery", "visited(rows@,rows@.len(),start,end,state,after,visit)", "true"),
        ("branch frontier", "next == stack.drop_last()+scheduled(children@,0,start,end)", "true"),
        ("reader binding", "#[trigger] read.ensures((stack.last(),),Ok(contents)) &&", "(#[trigger] read.ensures((stack.last(),),Ok(contents)) || true) &&"),
        ("complete traversal", "ensures completed(result,root,first,start@,end@,read,visit)", "ensures true"),
        ("error provenance", "failed(stack,s,start,end,read,visit,e),", "true,"),
    ]:
        yield (
            f"checkpoint walk loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_page_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_page.rs")
    consumer = Path("verification/hosted_checkpoint_page.rs")
    for label, clause, weaker in [
        ("child levels", "\n        &&& c.level as nat+1 == level", "\n        &&& true"),
        ("indexed row", "\n        &&& fetch.ensures((states[i],i as usize),Ok((states[i+1],c.lower_bound,c.object,c.totals)))", "\n        &&& true"),
        ("branch arity", "pair.1.len() == count", "true"),
        ("scheduled summary", "agrees(*page,h) && contents == h.node.contents()", "contents == h.node.contents()"),
        ("decoded payload", "agrees(*page,h) && contents == h.node.contents()", "agrees(*page,h)"),
        ("fetch error", "Err(e) => fetch.ensures((object(*page),),Err(e)) ||", "Err(e) => true ||"),
    ]:
        yield (
            f"checkpoint page loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_reference_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_reference.rs")
    consumer = Path("verification/hosted_checkpoint_reference.rs")
    for label, clause, weaker in [
        ("encoded slot", "out matches Some(l) ==> l.value()@ == wire(rel,slot)", "true"),
        ("encoded availability", "ensures out.is_some() == (slot <= u16::MAX), out matches Some(l)", "ensures out.is_some() ==> (slot <= u16::MAX), out matches Some(l)"),
        ("kind or label rejection", "ensures out == if position >= refs.len()", "ensures out.is_ok() ==> out == if position >= refs.len()"),
        ("exact target", "ensures out == if position >= refs.len()", "ensures out.is_err() ==> out == if position >= refs.len()"),
    ]:
        yield (
            f"checkpoint reference loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_totals_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_totals.rs")
    consumer = Path("verification/hosted_checkpoint_totals.rs")
    for label, clause, weaker in [
        ("writer bytes", "final(bytes)@ == old(bytes)@ + self.wire()", "true"),
        ("reader bytes", "crate::storage_fields::at(bytes@,*old(cursor) as int,t.wire())", "true"),
        ("full field acceptance", "out.is_ok() == (*old(cursor)", "out.is_ok() ==> (*old(cursor)"),
        ("short field rejection", "out.is_ok() == (*old(cursor)", "out.is_ok() <== (*old(cursor)"),
    ]:
        yield (
            f"checkpoint totals lose {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_key_field_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_key_field.rs")
    consumer = Path("verification/hosted_checkpoint_key_field.rs")
    for label, clause, weaker in [
        ("writer bytes", "wrote ==> final(bytes)@ == old(bytes)@ +", "false ==> final(bytes)@ == old(bytes)@ +"),
        ("decoded fence", "key@ == bytes@.subrange(start+4,start+4+size)", "true"),
        ("next field position", "*final(cursor) as int == start + 4 + size", "true"),
        ("short prefix or body rejection", "out.is_ok() == (start + 4", "out.is_ok() <== (start + 4"),
    ]:
        yield (
            f"checkpoint key field loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_child_consumers():
    child = Path("crates/astrid-storage/src/kv/tree/checkpoint_child.rs")
    reader = Path("crates/astrid-storage/src/kv/tree/checkpoint_key_field.rs")
    for label, path, target, clause, weaker in [
        ("success cursor", child, "child", "*final(cursor) as int == summary + 24", "true"),
        ("validator rejection cursor", child, "child", "summary <= bytes.len() && end == summary && exists", "summary <= bytes.len() && exists"),
        ("key error forwarding", child, "child", "key::failure(bytes,start,end,e)", "true"),
        ("totals error forwarding", child, "child", "super::checkpoint_totals::failure(bytes,summary,end,e)", "true"),
        ("key validation", child, "child", "field@ == row.0@ && r is Ok", "field@ == row.0@"),
        ("fence", child, "child", "row.0@ == bytes@.subrange(start+4,summary)", "true"),
        ("totals", child, "child", "crate::storage_fields::at(bytes@,summary,row.2.wire())", "true"),
        ("owning target", child, "child", "refs@[index as int].fields() == (edge::wire(edge::Relation::Child,index),row.1,super::ReferenceKind::Owns)", "true"),
        ("failure explanation", child, "child", "ChildError::Empty => end == summary+24 && exists", "ChildError::Empty => end == summary+24 || exists"),
        ("failure cursor", reader, "key_field", "&&& end == if start+4", "&&& true || end == if start+4"),
        ("failure type", reader, "key_field", "e == KeyError::Field(ReadError::Overflow(4))", "true"),
    ]:
        yield (
            f"checkpoint branch binding loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker),
            Path(f"verification/hosted_checkpoint_{target}.rs"),
        )


def checkpoint_branch_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_branch.rs")
    consumer = Path("verification/hosted_checkpoint_branch.rs")
    for label, clause, weaker in [
        ("number of children", "level > 0 && pair.1.len() == count &&", "level > 0 &&"),
        ("owning reference", "refs[idx].fields() == (edge::wire", "false ==> refs[idx].fields() == (edge::wire"),
        ("encoded key", "child.lower_bound@ == bytes.subrange", "false ==> child.lower_bound@ == bytes.subrange"),
        ("derived child level", " && child.level as int + 1 == level", ""),
        ("adjacent fields", "end as int == pos + 24 && child.level", "child.level"),
        ("first field position", " && positions[0] == first", ""),
        ("last field position", " && positions.last() == end", ""),
        ("failing child reason", "checkpoint_child::failure(\n                bytes@,refs@,rows.len() as usize,s as int,pair.0 as int,validate,reason)", "true"),
    ]:
        yield (
            f"checkpoint branch layout loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_summary_consumers():
    finish = Path("crates/astrid-storage/src/kv/tree/checkpoint_summary.rs")
    branch = Path("crates/astrid-storage/src/kv/tree/checkpoint_branch.rs")
    consumer = Path("verification/hosted_checkpoint_summary.rs")
    for label, path, clause, weaker in [
        ("finish result", finish, "ensures out == finished(end,length,level,children,totals)", "ensures out.is_err() ==> out == finished(end,length,level,children,totals)"),
        ("finish rejection", finish, "ensures out == finished(end,length,level,children,totals)", "ensures out.is_ok() ==> out == finished(end,length,level,children,totals)"),
        ("header rejection", branch, "(out matches Err(DecodeError::Header)) == !self.valid(refs.len() as usize)", "(out matches Err(DecodeError::Header)) ==> !self.valid(refs.len() as usize)"),
        ("ordered fences", branch, "&&& checkpoint_summary::ordered(b.children@,self.count as nat)", "&&& true"),
        ("accounted totals", branch, "&&& checkpoint_summary::counts(b.children@,self.count as nat) ==", "&&& false ==> checkpoint_summary::counts(b.children@,self.count as nat) =="),
    ]:
        yield (
            f"checkpoint branch summary loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_header_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_header.rs")
    consumer = Path("verification/hosted_checkpoint_header.rs")
    for label, clause, weaker in [
        ("written bytes", "out ==> final(bytes)@ == old(bytes)@ + wire(kind,h)", "true"),
        ("decoded bytes", "Ok(pair) => present(bytes@,kind,pair.1,pair.0)", "Ok(pair) => true"),
        ("prefix rejection", "Err(e) => prefix_error(bytes@,kind,e)", "Err(e) => true"),
        ("body error evidence", "h.outcome(bytes,refs,s,validate,Err(e))", "true"),
        ("branch prefix error evidence", "Err(RecordError::Prefix(e)) => prefix_error(bytes@,Kind::Branch,e)", "Err(RecordError::Prefix(e)) => true"),
        ("raw branch binding", "present(bytes@,Kind::Branch,h,s) &&\n            h.outcome(bytes,refs,s,validate,Ok(b))", "present(bytes@,Kind::Branch,h,s)"),
    ]:
        yield (
            f"checkpoint header loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_value_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_value.rs")
    consumer = Path("verification/hosted_checkpoint_value.rs")
    for label, clause, weaker in [
        ("inline bytes", "data@ == bytes.subrange(start+9,end)", "true"),
        ("spilled target", "refs[position as int].fields() == (edge::wire", "false ==> refs[position as int].fields() == (edge::wire"),
        ("physical cursor", "next as int == position as int+1", "true"),
        ("error cause", "&& failure(bytes@,*old(cursor)", "&& false ==> failure(bytes@,*old(cursor)"),
        ("writer bytes", "out.is_ok() ==> final(bytes)@ == old(bytes)@ + wire(*value)", "true"),
        ("writer owning edge", "final(refs)@.last().fields() == (edge::wire", "false ==> final(refs)@.last().fields() == (edge::wire"),
    ]:
        yield (
            f"checkpoint value loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker), consumer,
        )


def checkpoint_entries_consumers():
    entries = Path("crates/astrid-storage/src/kv/tree/checkpoint_entries.rs")
    record = Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf_record.rs")
    for label, path, name, clause, weaker in [
        ("declared count", entries, "entries", "Ok(rows) => rows.len() == count && exists", "Ok(rows) => exists"),
        ("initial cursors", entries, "entries", " && path[0] == (start,0usize)", ""),
        ("final cursors", entries, "entries", " && path.last() == end", ""),
        ("key acceptance", entries, "entries", "k@ == row.key@ && r is Ok", "k@ == row.key@"),
        ("value error evidence", entries, "entries", "body <= bytes.len() && value::failure(bytes,body,end as int,refs,start.1,i,e) &&", "body <= bytes.len() &&"),
        ("leaf finish evidence", Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf_summary.rs"), "leaf_record", "ensures out == outcome(rows,totals)", "ensures out.is_ok() ==> out == outcome(rows,totals)"),
        ("key association", entries, "entries", " && row.key@ == bytes.subrange(start.0 as int+4,body)", ""),
        ("value association", entries, "entries", "&&& value::decoded(bytes,body,end.0 as int", "&&& false ==> value::decoded(bytes,body,end.0 as int"),
        ("trailing byte evidence", entries, "entries", "rows.len() == count && s.0 != bytes.len()", "rows.len() == count"),
        ("remaining references", entries, "entries", "&& s.1 != refs.len()", ""),
        ("accepted charge", record, "leaf_record", "&&& summary::usage(leaf.entries@,h.count as nat) ==", "&&& false ==> summary::usage(leaf.entries@,h.count as nat) =="),
        ("failure provenance", record, "leaf_record", "&& summary::outcome(rows,h.totals) == Err(e),", "&& true,"),
    ]:
        yield (
            f"checkpoint leaf decode loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker),
            Path(f"verification/hosted_checkpoint_{name}.rs"),
        )


def checkpoint_record_consumers():
    path = Path("crates/astrid-storage/src/kv/tree/checkpoint_record.rs")
    for label, clause, weaker in [
        ("metadata checks", "out == Err(EnvelopeError::Header)", "true"),
        ("leaf dispatch", "out == Ok(PageKind::Leaf)", "true"),
        ("branch dispatch", "out == Ok(PageKind::Branch)", "true"),
        ("kind rejection", "out == Err(EnvelopeError::Kind)", "true"),
        ("charge overflow", "out == Err(SizeError::Overflow)", "true"),
        ("oversize rejection", "out == Err(SizeError::Oversize)", "true"),
        ("scheduled identity", "out matches Ok(handle) && handle.object == id", "out matches Ok(handle)"),
        ("decoded page", "handle.node == node", "true"),
        ("admitted payload", "parsed(record,handle.node,validate)", "true"),
        ("admitted identity", "handle.object == id && parsed(record", "parsed(record"),
    ]:
        yield (
            f"checkpoint envelope loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker),
            Path("verification/hosted_checkpoint_record.rs"),
        )

    for label, clause, weaker, consumer in [
        ("leaf refusal", "leaf::body(f.2,f.3,s,h,validate,Err(e))", "true", "leaf_record"),
        ("branch refusal", "h.field_outcome(f.2,f.3,s,validate,Err(b))", "true", "header"),
        ("overflow cause", "SizeError::Overflow => record.retained_cost() > u64::MAX", "SizeError::Overflow => true", "leaf_record"),
        ("oversize cause", "NODE_MAX_RETAINED_BYTES < record.retained_cost() <= u64::MAX && match n", "match n", "header"),
    ]:
        yield (
            f"checkpoint envelope loses {label}", path,
            lambda text, clause=clause, weaker=weaker: replace_once(text, clause, weaker),
            Path(f"verification/hosted_checkpoint_{consumer}.rs"),
        )


def checkpoint_decode_consumers():
    yield from checkpoint_page_consumers()
    yield from checkpoint_reference_consumers()
    yield from checkpoint_totals_consumers()
    yield from checkpoint_key_field_consumers()
    yield from checkpoint_child_consumers()
    yield from checkpoint_branch_consumers()
    yield from checkpoint_summary_consumers()
    yield from checkpoint_header_consumers()
    yield from checkpoint_value_consumers()
    yield from checkpoint_entries_consumers()
    yield from checkpoint_record_consumers()
