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

    append = Path("verification/hosted_arena_append.rs")
    for label, source, clause, weaker, target in [
        ("canonical delta", marker, "ensures marker_bytes(out.0.contents().2,key@), out.1", "ensures true, out.1", append),
        ("submitted payload", append, "ensures out@==v@ {v.as_slice()}", "ensures true {v.as_slice()}", append),
        ("physical contents", append, "&&& crate::hosted_delta_mutation::marker_bytes(\n        crate::hosted_journal_history::component_bytes(image,loc),address)", "&&& true", admission),
        ("reopened file image", admission, "open.ensures((f,),m) ==> m.image()==f.image() &&", "open.ensures((f,),m) ==> true &&", admission),
        ("indexed frame", admission, "index.insert(id,loc);", "let _discarded_location = loc;", admission),
    ]:
        yield (
            f"appended token marker loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), target,
        )
