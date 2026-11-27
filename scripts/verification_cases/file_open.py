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
    table = Path("crates/astrid-capsule/src/engine/wasm/storage_handles.rs")
    for label, before, after in [
        ("registration refusal", "fresh == !old(self).has(key@)", "fresh ==> !old(self).has(key@)"),
        ("lookup identity", "Some(v) ==> self.binds(key@, *v)", "Some(v) ==> self.has(key@)"),
        ("lookup availability", "value.is_some() == self.has(key@)", "value.is_some() ==> self.has(key@)"),
        ("retire binding", "old(self).binds(key@,v) && old(self).removed", "old(self).removed"),
        ("retired identity", "self.contents()[key] == value, next.contents()", "true, next.contents()"),
        ("remaining handles", "next.contents() == self.contents().remove(key),\n    {", "!next.contents().contains_key(key),\n    {"),
    ]:
        yield (f"storage close loses {label}", table,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
    for label, before, after in [
        ("publication availability", "out.is_some() == (self.can_write() && self.changed())",
         "out.is_some() ==> (self.can_write() && self.changed())"),
        ("published bytes", "self.arguments().1@ == self.buffered(),", "true,"),
        ("publication destination", "*self.arguments().0 == self.destination(),", "true,"),
        ("backend result", "write.ensures(self.arguments(),r)", "true"),
    ]:
        yield (f"storage close loses {label}", storage_file,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
    for source, function in [
        ("hosted_physical_path.rs", "gated_mount"),
        ("hosted_vfs_address.rs", "admitted_worker"),
        ("hosted_vfs_address.rs", "after_rebind"),
        ("hosted_file_open.rs", "guest"),
        ("hosted_file_open.rs", "storage_replace"),
        ("hosted_file_open.rs", "storage_handles"),
        ("hosted_file_open.rs", "retire_observed"),
    ]:
        proof = Path("verification", source)

        def contradict(text, name=function):
            start = text.index(f"\nfn {name}")
            opening = text.index("\n{\n", start) + 3
            return text[:opening] + "    assert(false);\n" + text[opening:]

        yield f"storage close vacuity check for {function}", proof, contradict, proof
    replacement = Path("crates/astrid-storage/src/filesystem/replacement.rs")
    for label, before, after in [
        ("parent admission", "Ok(write) => parent.ensures((path,),Ok(())) &&", "Ok(write) =>"),
        ("file admission", "&& directory.ensures((path,),Ok(false))\n            && key", "\n            && key"),
        ("key derivation", "key.ensures((path,),Ok(write.arguments().1))", "true"),
        ("owner and branch", "write.arguments().0 == destination", "true"),
        ("input bytes", "write.arguments().2 == bytes", "true"),
        ("parent refusal", "Err(error) => parent.ensures((path,),Err(error))", "Err(error) => true"),
        ("backend return", "put.ensures(self.arguments(),result)", "true"),
    ]:
        yield (f"catalog replacement loses {label}", replacement,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
    name = Path("crates/astrid-storage/src/content/name.rs")
    for label, before, after in [
        ("catalog spelling", "name.spelling() == path@ &&", "true &&"),
        ("empty key rejection", "Err(ContentNameError::Empty) => path@.len() == 0", "Err(ContentNameError::Empty) => true"),
        ("null rejection", "Err(ContentNameError::ContainsNull) => path@.len() != 0 && vstd::utf8::encode_utf8(path@).contains(0u8)",
         "Err(ContentNameError::ContainsNull) => true"),
        ("emitted spelling", "ensures text@ == self.spelling(),\n    { self.0 }", "ensures true,\n    { self.0 }"),
    ]:
        yield (f"catalog replacement loses {label}", name,
               lambda s, a=before, b=after: replace_once(s, a, b), consumer)
