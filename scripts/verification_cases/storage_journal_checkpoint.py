"""Consumer checks for replayed journal frames carried through WAL retirement."""

from pathlib import Path

from .common import replace_once


def consumer_defects():
    frames = Path("crates/astrid-storage/src/engine/durable/arena_frame.rs")
    checkpoint = Path("verification/hosted_recovery_barrier.rs")
    consumer = Path("verification/hosted_wal_writer_trace.rs")
    for label, source, clause, weaker in [
        ("written bytes", frames, "exists|bytes:Seq<u8>| final(file).image()==old(file).image()+bytes &&", "exists|bytes:Seq<u8>| true &&"),
        ("location count", frames, "out matches Ok(rows) ==> rows.len()==input.len() && final(file).cursor()", "out matches Ok(rows) ==> final(file).cursor()"),
        ("write target", frames, "ensures final(file).target()==old(file).target(),\n        out matches Ok(rows)", "ensures true,\n        out matches Ok(rows)"),
        ("overflow cause", frames, "out matches Err(BatchError::Overflow) ==> final(file).image()==old(file).image() &&", "out matches Err(BatchError::Overflow) ==> final(file).image()==old(file).image() ||"),
        ("checkpoint target", checkpoint, "&&& s.roots_target()==old(files).roots_target()", "&&& true"),
        ("checkpoint root bytes", checkpoint, "&&& stable.get(Target::Roots)==pending.get(Target::Roots)", "&&& true"),
    ]:
        yield (
            f"checkpointed journal loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), consumer,
        )

    reader = Path("crates/astrid-storage/src/engine/durable/frame_repair.rs")
    restart = Path("verification/hosted_acknowledged_root.rs")
    for label, source, clause, weaker, target in [
        ("header bytes", reader, "bytes@==old(self).image().subrange(old(self).position(),final(self).position()),\n            out matches Err(e) ==> old(self).failed(old(self).position(),52,e);", "true,\n            out matches Err(e) ==> old(self).failed(old(self).position(),52,e);", restart),
        ("payload bytes", reader, "bytes@==old(reader).image().subrange(old(reader).position(),final(reader).position()) &&", "true &&", restart),
        ("valid checksum", reader, "(exists|b:&[u8]| b@==bytes@ && #[trigger] hash.ensures((magic,header.payload_len,b),header.checksum)),", "true,", restart),
        ("checksum refusal", reader, "sum!=header.checksum && #[trigger] hash.ensures", "#[trigger] hash.ensures", restart),
        ("restart history", restart, "prior.insert(key,(next,start))} else {prior}", "final(restart)@} else {prior}", consumer),
        ("conflicting restart", restart, "result matches Some(accepted) ==> accepted==(actual==expected && next.generation.value()==generation)", "result matches Some(accepted) ==> ((actual==expected && next.generation.value()==generation) ==> accepted)", consumer),
    ]:
        yield (
            f"cold journal replay loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )

    graph = Path("verification/hosted_recovered_header.rs")
    journal = Path("verification/hosted_journal_history.rs")
    marker = Path("verification/hosted_delta_mutation.rs")
    admission = Path("verification/hosted_token_recovery.rs")
    for label, source, clause, weaker, target in [
        ("arena target", checkpoint, "&&& s.arena_target()==old(files).arena_target()", "&&& true", consumer),
        ("stable arena bytes", checkpoint, "&&& stable.get(Target::Arena)==pending.get(Target::Arena)", "&&& true", consumer),
        ("decoded owner", graph, "graph.owner==*owner && history@.contains_key(*owner)", "history@.contains_key(*owner)", consumer),
        ("decoded component", graph, "ensures out.is_some()==self.component.is_some(),", "ensures true,", consumer),
        ("indexed payload", journal, "ensures r.contents().2==component_bytes(image,row.1),", "ensures true,", admission),
        ("decoded marker write", marker, """ensures head matches crate::delta_chain::Head::Delta{mutations,..} && mutations.len()==1 &&
        mutations@[0].key@==address && (mutations@[0].value matches Some(ValueSlot::Inline(data)) && data@==seq![1u8]) &&
        crate::overlay_batch::after_rows(mutations@,1,address,None)==Some(true),""", "ensures true,", admission),
        ("exact token address", marker, "&&& bytes.subrange(41,tag)==address && bytes[tag]==delta::INLINE", "&&& bytes[tag]==delta::INLINE", marker),
    ]:
        yield (
            f"recovered arena marker loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )

    append = Path("verification/hosted_marker_append.rs")
    for label, source, clause, weaker, target in [
        ("canonical delta", marker, "ensures marker_bytes(out.0.contents().2,key@), out.1", "ensures true, out.1", append),
        ("submitted payload", append, "ensures out@==v@ {v.as_slice()}", "ensures true {v.as_slice()}", append),
        ("physical contents", append, "&&& crate::hosted_delta_mutation::marker_bytes(\n        crate::hosted_journal_history::component_bytes(image,loc),address)", "&&& true", append),
        ("reopened file image", append, "open.ensures((f,),m) ==> m.image()==f.image() &&", "open.ensures((f,),m) ==> true &&", append),
        ("indexed frame", append, "index.insert(id,loc);", "let _discarded_location = loc;", append),
        ("existing location", append, "Ok((id,loc,MarkerRestart::AlreadyIndexed(*earlier)))", "Ok((id,*earlier,MarkerRestart::AlreadyIndexed(loc)))", append),
        ("index after reopen error", append, "Ok((id,loc,MarkerRestart::Recovered(media,graph,decision)))", "if decision.is_err() {index.remove(&id);}\n    Ok((id,loc,MarkerRestart::Recovered(media,graph,decision)))", append),
        ("admission decision", append, "MarkerRestart::Recovered(media,graph,decision)))", "MarkerRestart::Recovered(media,graph,Ok(Admission::Allowed))))", append),
    ]:
        yield (
            f"appended token marker loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )

    group = Path("verification/hosted_wal_object_root.rs")
    codec = Path("crates/astrid-storage/src/engine/durable/wal/object_storage.rs")
    transfer = Path("verification/hosted_wal_writer_trace.rs")
    for label, source, clause, weaker in [
        ("scanned objects", Path("crates/astrid-storage/src/engine/durable/wal/transaction.rs"),
         "ensures records@ == self.contents().objects,", "ensures true,"),
        ("stable WAL target", transfer, "(target@)(media)==sink.wal_target(),\n{", "true,\n{"),
        ("stored object boundary", group, "object_start:(o.next-(72+o.body.len())) as u64", "object_start:o.next as u64"),
        ("stored root boundary", group, "root_start:(r.next-(72+r.body.len())) as u64", "root_start:r.next as u64"),
        ("compression selection", codec, "n==compressed as int+PREFIX && n<canonical", "n==compressed as int+PREFIX"),
        ("length prefix", codec, "ensures final(stored)@==vstd::bytes::spec_u64_to_le_bytes(length)+block@,", "ensures true,"),
        ("compressed block", codec, "block@==body@.skip(8),", "true,"),
        ("marker arena payload", append, "final(file).image().subrange(at,at+loc.payload_len)==payload@", "true"),
        ("released owner", group, "parse_written(&group.root,&name,scheme,expected,replacement)", "parse_written(&group.object,&name,scheme,expected,replacement)"),
    ]:
        yield (
            f"acknowledged object group loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), group,
        )

    publication = Path("verification/hosted_kv_root_publication.rs")
    for label, clause, expected, substituted in [
        ("commit state edge", "header_graph::state_edge(rows[bound.2.commit]) matches Some(e) && e.fields()==(header_graph::STATE@,self.state,ReferenceKind::Owns)", ",self.state,", ",self.component,"),
        ("state component edge", "header_graph::kv_edge(rows[self.state]) matches Some(e) && e.fields()==(header_graph::KV@,self.component,ReferenceKind::Owns)", ",self.component,", ",self.state,"),
    ]:
        # Require a false edge destination in the graph predicate.
        yield (
            f"selected marker publication loses {label}", publication,
            lambda s, a=clause, b=clause.replace(expected, substituted): replace_once(s, a, b),
            publication,
        )
    for label, clause, weaker in [
        ("authenticated declaration", "forall|id:ObjectId| g.records@.contains_key(id) ==> #[trigger] identify.ensures((&g.records@[id],),id)", "true"),
        ("current owner root", "(if pending@.contains_key(owner) {Some(pending@[owner])} else {published@.get(owner)})==prior &&", "true &&"),
    ]:
        yield (
            f"selected marker publication loses {label}", publication,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), group,
        )

    # Removing a producer guarantee must fail in its consuming theorem.
    yield (
        "selected marker publication loses retained lineage", publication,
        lambda s: replace_once(s, "&& g.retained(state_refs@,commit_refs@) &&", "&& true &&"),
        group,
    )
    yield (
        "selected marker publication loses recovered closure",
        Path("crates/astrid-storage/src/engine/durable/closure_load.rs"),
        lambda s: replace_once(s, "&&& walk::closed(root,Set::empty(),graph,ids)", "&&& true"),
        publication,
    )

    placement = Path("crates/astrid-storage/src/engine/durable/closure_load.rs")
    for label, clause, weaker in [
        ("uncached path", "Placement::Unreachable=>!reachable@.contains(id)", "Placement::Unreachable=>true"),
        ("pending contents", "&& *record==pending@[id],", ","),
        ("arena location", "&& location==index@[id],", ","),
        ("commit identity", "&& id==commit,", ","),
    ]:
        yield (
            f"live marker placement loses {label}", placement,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), publication,
        )

    for label, clause, weaker in [
        ("pending equality", "(if *r==*record {out matches Ok(None)} else {out matches Err(PlacementError::Collision(k)) && k==id})", "(if *r==*record {out matches Ok(None)} else {true})"),
        ("indexed contents", "Ok(None)=>read.ensures((id,loc),Ok(*record)),", "Ok(None)=>true,"),
        ("indexed error identity", "Err(PlacementError::Read(e))=>read.ensures((id,loc),Err(e)),", "Err(PlacementError::Read(_))=>true,"),
    ]:
        yield (
            f"prepared graph row loses {label}", placement,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), publication,
        )

    batch_writer = Path("verification/hosted_wal_batch_writer.rs")
    for label, clause, weakness in [
        ("object ordinal", "o.encoding.flag(),sequence,count as u64,o.body.len()", "o.encoding.flag(),sequence,0,o.body.len()"),
        ("submitted interval", "wal.append_record(&stream[start..end])", "wal.append_record(&stream[..end])"),
        ("commit frame", "wal.append_record(&stream[start..])", "wal.append_record(&stream[start..start])"),
        ("captured offset", "start:base+(row.next-72-row.body.len()) as u64", "start:base+row.next as u64"),
        ("stable readback", "ensures out.1@==stream@ && out.0.image()", "ensures true && out.0.image()"),
    ]:
        yield (
            f"acknowledged variable batch loses {label}", batch_writer,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), batch_writer,
        )
