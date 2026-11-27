"""Downstream obligations for the file charge and immutable content edge."""
from pathlib import Path

from .common import replace_once


def defects():
    source = Path("crates/astrid-storage/src/content_dag/file_wire.rs")
    trace = Path("verification/hosted_file_descriptor.rs")
    for name, old, new in [
        ("writer may change the descriptor", "ensures bytes@ == self.wire()", "ensures bytes.len() == LENGTH"),
        ("reader may refuse a canonical header", "out.is_some() == (bytes.len()", "out.is_some() ==> (bytes.len()"),
        ("catalog may select a different file", "#[trigger] load.ensures((file,),Ok(r)) && file_record(r,version)", "#[trigger] file_record(r,version)"),
        ("catalog may accept another record kind", "&& file_record(r,version)", "&& true"),
        ("catalog may charge another length", "&& h.logical == declared", "&& true"),
        ("catalog may mask a loader error", "==> load.ensures((file,),Err(e))", "==> true"),
        ("catalog may report a spurious mismatch", "h.wire() == r.contents().2 && h.logical != declared,", "h.wire() == r.contents().2,"),
        ("nonempty file may point elsewhere", "r.3[0].fields() == (CONTENT@,id,super::ReferenceKind::Owns)", "r.3[0].fields().0 == CONTENT@"),
        ("empty file may carry references", "count == 0 && root.is_none() && r.3.len() == 0", "count == 0 && root.is_none()"),
    ]:
        yield (
            f"file descriptor {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )
