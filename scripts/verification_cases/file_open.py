"""Check that the guest file proof consumes access and native builder guarantees."""
from pathlib import Path

from .common import replace_once


def defects():
    access = Path("crates/astrid-capsule/src/engine/wasm/host/fs/access.rs")
    options = Path("crates/astrid-vfs/src/open_options.rs")
    consumer = Path("verification/hosted_file_open.rs")
    for label, before, after in [
        ("retained access", "access == self && check.ensures", "check.ensures"),
        ("policy acceptance", "check.ensures((self.policy(),path),Ok(guard))", "true"),
        ("policy refusal", "check.ensures((self.policy(),path),Err(e))", "true"),
        ("dispatch availability", "out.is_some() == (self is Read", "out.is_some() ==> (self is Read"),
        ("dispatch arguments", "apply.ensures((dir,path,self is Write,self is Write),r)", "true"),
    ]:
        yield (f"guest file open loses {label}", access,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
    flags = ["b.flags().0", "b.flags().1 == write", "b.flags().2 == write", "b.flags().3 == truncate"]
    for index, label in enumerate(("read", "write", "create", "truncate")):
        before = "ensures exists|b:B| b.flags() == (true,write,write,truncate)"
        after = "ensures exists|b:B| " + " && ".join(flags[:index] + flags[index + 1:])
        yield (f"guest file open loses native {label} option", options,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
    storage_file = Path("crates/astrid-capsule/src/engine/wasm/storage_file.rs")
    for label, before, after in [
        ("destination", "f.destination() == path && f.position()", "true && f.position()"),
        ("writable flag", "f.can_write() == write,", "true,"),
        ("empty replacement", "f.buffered().len() == 0 && f.changed()", "f.changed()"),
        ("replacement publication", "f.buffered().len() == 0 && f.changed()", "f.buffered().len() == 0"),
        ("preserved contents", "b@ == f.buffered()", "true"),
        ("missing refusal", "out matches Err(OpenError::Missing)", "out.is_err()"),
        ("truncate refusal", "out matches Err(OpenError::TruncateDenied)", "out.is_err()"),
    ]:
        yield (f"storage file open loses {label}", storage_file,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
