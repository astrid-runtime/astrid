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
