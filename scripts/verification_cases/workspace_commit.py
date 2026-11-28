"""Downstream requirements for the UID-bound workspace finish path."""
from pathlib import Path

from .common import replace_once


def defects():
    source = Path("crates/astrid-capsule/src/context/workspace_commit.rs")
    trace = Path("verification/hosted_workspace_commit.rs")
    for name, old, new in [
        ("can accept a stale lease", "out == if observed == *expected { Ok(observed) } else { Err(LeaseError::Mismatch) }", "observed == *expected ==> out == Ok(observed)"),
        ("can return an arbitrary branch", "{ Ok(observed) } else { Err(LeaseError::Mismatch) }", "{ out } else { Err(LeaseError::Mismatch) }"),
        ("can accept a missing lease", "else { out == Err(LeaseError::Missing) }", "else { true }"),
        ("can omit the storage operation", "final(writer).calls() == old(writer).calls().push((op,owner,branch))", "true"),
        ("can mask a storage error", "&& old(writer).outcome(op,owner,branch,r)", "&& true"),
        ("can write on refusal", "out.is_none() && final(writer).calls() == old(writer).calls()", "out.is_none()"),
    ]:
        yield (
            f"workspace commit {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/workspace/reference_transition.rs")
    trace = Path("verification/hosted_workspace_references.rs")
    for name, old, new in [
        ("live publication may lose prior references", "ensures final(references)@.drop_last() == old(references)@,", "ensures true,"),
        ("live publication may name another branch", "branch_label(label,id) && record == target", "true && record == target"),
        ("live publication may name another record", "&& record == target && kind", "&& true && kind"),
        ("live publication may append a non-owning edge", "record == target && kind == ReferenceKind::Owns", "record == target && true"),
        ("recovery may miss a valid receipt", "(out == Some(id)) == #[trigger] receipt_label", "(out == Some(id)) ==> #[trigger] receipt_label"),
        ("live lookup can accept a promotion receipt", "(out == Some(id)) == #[trigger] branch_label", "(out == Some(id)) <== #[trigger] branch_label"),
        ("encoder need not emit a recoverable receipt", "ensures receipt_label(bytes@,id),", "ensures true,"),
        ("receipt may own the wrong object", "&&& reference.fields().1 == target", "&&& true"),
        ("receipt can have the wrong relation kind", "&&& reference.fields().2 == ReferenceKind::Owns", "&&& true"),
        ("rollback can change unrelated references", "None => final(references)@ == survivors", "None => true"),
        ("promotion can change the surviving prefix", "final(references)@ == #[trigger] survivors.push(r)", "final(references)@.len() > 0 && final(references)@.last() == r"),
    ]:
        yield (
            f"workspace references {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/commit_candidate.rs")
    for name, old, new in [
        ("preserved commit reference can change", "&&& after.take(before.len() as int) == before", "&&& true"),
        ("extra commit links can be appended", "&&& after.len() == before.len() + (if expected.is_some() { 2int } else { 1int })", "&&& after.len() >= before.len() + (if expected.is_some() { 2int } else { 1int })"),
        ("owner can change", "p == self.parts().0 &&", "true &&"),
        ("expected root can change", "r == self.parts().1", "true"),
        ("commit can differ from encoder result", "&& seal.ensures((self.parts().2,),Ok((id,b)))", "&& true"),
        ("error can differ from encoder result", "out matches Err(e) ==> seal.ensures((self.parts().2,),Err(e))", "true"),
        ("parent relation can change", "after[before.len() as int].fields() == (PARENT@,root.commit,ReferenceKind::Lineage)", "after[before.len() as int].fields().1 == root.commit"),
        ("state object can change", "after.last().fields() == (STATE@,state,ReferenceKind::Owns)", "after.last().fields().2 == ReferenceKind::Owns"),
    ]:
        yield (
            f"content commit {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/workspace/retry.rs")
    for name, old, new in [
        ("historical events can be discarded", "ensures final(backend).events().take(old(backend).events().len() as int) == old(backend).events(),", "ensures true,"),
        ("prior attempts can target another branch", "trace[2*i+1] == Event::Apply(owner,id,h,Ok(Step::Conflict))", "true"),
        (
            "completion can use another sampled header",
            "trace[2*(n as int)+1] == Event::Apply(owner,id,h,match out {\n"
            "                Ok(t) => Ok(Step::Done(t)), Err(e) => Err(e),\n            })",
            "match trace[2*(n as int)+1] { Event::Apply(q,key,_,r) => q == owner && key == id && "
            "r == match out { Ok(t) => Ok(Step::Done(t)), Err(e) => Err(e) }, _ => false }",
        ),
        ("failed read may report a different error", "trace[2*(n as int)] == Event::Read(owner,Err(e))", "true"),
    ]:
        yield (
            f"workspace retry {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/header_cache.rs")
    for name, old, new in [
        ("cache hit can return another header", "(out matches Ok(h) && lookup.ensures((owner,r.commit),Some((Some(r),h))))", "out.is_ok()"),
        ("missing published root can mask a decode failure", "None => decode.ensures((owner,root),out)", "None => true"),
        ("stale cache entry can mask a decode failure", "(decode.ensures((owner,root),out) &&", "(true &&"),
        ("matching current entry can be discarded", "h:H| observed != root && #[trigger]", "h:H| true && #[trigger]"),
    ]:
        yield (
            f"content header {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    yield (
        "content header published lookup can select a peer root",
        Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
        lambda s: replace_once(s, "ensures root == if roots@.contains_key(*owner) { Some(roots@[*owner]) } else { None },",
                               "ensures root.is_some() == roots@.contains_key(*owner),"),
        trace,
    )

    source = Path("crates/astrid-storage/src/storage_model/header_graph.rs")
    for name, old, new in [
        ("commit can belong to another lookup", "&&& load.ensures((owner,root.commit),Ok(g.commit))\n", "&&& true\n"),
        ("state can belong to another lookup", "&&& load.ensures((owner,g.state_id),Ok(g.state))\n", "&&& true\n"),
        ("success can substitute a different matching edge", "&& state_edge(*g.commit) == Some(r)", "&& true"),
        ("failure can substitute a different matching edge", "&& state_edge(*c) == Some(edge)", "&& true"),
        ("state edge can point elsewhere", "#[trigger] r.fields() == (STATE@,g.state_id,super::ReferenceKind::Owns)", "#[trigger] r.fields().0 == STATE@"),
        ("state can carry a different shape", "&&& structural(*g.state,ObjectKind::PrincipalState,v)", "&&& true"),
        ("read error may come from another object", "out matches Err(Error::Read(error)) ==> load.ensures((owner,root.commit),Err(error))", "out matches Err(Error::Read(error)) ==> true"),
    ]:
        yield (
            f"content graph {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    for label, clause, weaker in [
        ("absent component", "None => kv_edge(*g.state).is_none()", "None => true"),
        ("component address", "edge.fields() == (KV@,id,super::ReferenceKind::Owns)",
         "edge.fields().0 == KV@"),
        ("structural rejection", "==> invalid_at(owner,root,v,load,id,reason),\n        out matches Err(KvError",
         "==> true,\n        out matches Err(KvError"),
        ("non-owning rejection", "edge.fields().2 != super::ReferenceKind::Owns),",
         "true),"),
    ]:
        yield (
            f"captured KV graph loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), trace,
        )

    journal = Path("verification/hosted_journal_history.rs")
    for label, path, clause, weaker in [
        ("root generation and commit", journal, "roots@[p] == history@[p].0", "true"),
        ("owning closure", journal, "crate::journal_preload::closed_on(table@,table@.dom()) &&", "true &&"),
        ("physical record identity", journal,
         "#[trigger] media_record(media.image(),(k,index@[k]),format.scheme,table@[k])) &&",
         "index@.contains_key(k)) &&"),
        ("selected component row", source, "g.state.contents().3.contains(edge) &&", "true &&"),
    ]:
        yield (
            f"recovered header provenance loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_recovered_header.rs"),
        )

    projection = Path("crates/astrid-storage/src/kv/tree/memo_projection.rs")
    for label, clause, weaker in [
        ("success address", "#[trigger] resolve.ensures((owner,id),Ok(t))",
         "true"),
        ("error origin", "resolve.ensures((owner,id),Err(e)),",
         "true,"),
        ("empty graph selection", "graph.ensures((owner,root),Ok((g,None))) && empty.ensures((),t)",
         "empty.ensures((),t)"),
    ]:
        yield (
            f"captured header projection loses {label}", projection,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), trace,
        )

    yield (
        "captured KV graph loses canonical row identity", Path("crates/astrid-storage/src/storage_model/reference_lookup.rs"),
        lambda s: replace_once(s, "ensures selected(refs,refs[i].fields().0,lo,hi) == Some(refs[i])",
                               "ensures selected(refs,refs[i].fields().0,lo,hi).is_some()"), trace,
    )

    yield (
        "content graph canonical state edge can be missed", Path("crates/astrid-storage/src/storage_model/reference_lookup.rs"),
        lambda s: replace_once(s, "forall|i:int| #[trigger] positioned(refs@,label@,i) ==> (out matches Some(r) && *r == refs@[i]),", "true,"), trace,
    )

    component_source = Path("crates/astrid-storage/src/content/store/components.rs")
    component_trace = Path("verification/hosted_header_components.rs")
    for name, old, new in [
        ("can accept non-owning state relations", "&&& kind == super::ReferenceKind::Owns", "&&& true"),
        ("can substitute the selected catalog", "parts.catalog == last_catalog(obs) && forall", "true && forall"),
        ("can substitute the aggregate charge", "parts.other_bytes == #[trigger] total(obs)", "parts.other_bytes >= #[trigger] total(obs)"),
        ("can discard preserved references", "&&& parts.preserved@.map_values(|r:ObjectReference| r.fields()) == refs@.filter(|r:ObjectReference| r.fields().0 != CONTENT@).map_values(|r:ObjectReference| r.fields())", "&&& true"),
        ("can substitute a KV charge", "charge.ensures((owner,Charge::Kv,r,root),Ok(n))", "true"),
        ("can substitute a workspace charge", "charge.ensures((owner,Charge::Workspace,r,root),Ok(n))", "true"),
        ("can report overflow without exceeding the budget", "Ok(n)) && bytes+n > u64::MAX", "Ok(n))"),
        ("can substitute the catalog error", "catalog.ensures((owner,id,root),Err(err))", "true"),
    ]:
        yield (
            f"owner components {name}", component_source,
            lambda s, a=old, b=new: replace_once(s, a, b), component_trace,
        )

    source = Path("crates/astrid-storage/src/content/catalog/summary.rs")
    trace = Path("verification/hosted_catalog_charge.rs")
    for name, old, new in [
        ("can omit the name charge", "s.quota_bytes == logical + name.len()", "s.quota_bytes >= logical"),
        ("can refuse a valid leaf", "out.is_some() == (logical", "out.is_some() ==> (logical"),
        ("can discard a child charge", "s.quota_bytes == left.quota_bytes + right.quota_bytes", "s.quota_bytes >= left.quota_bytes"),
        ("can refuse a valid join", "out.is_some() == (left.logical_bytes", "out.is_some() ==> (left.logical_bytes"),
    ]:
        yield (
            f"catalog accounting {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/quota_transition.rs")
    for name, old, new in [
        ("owner may substitute a refusal", "out == decision(other + previous, other + next, limit)", "out.is_ok() == decision(other + previous, other + next, limit).is_ok()"),
        ("promotion may ignore an impossible branch charge", "out == if branch > components { Err(Refusal::AccountingOverflow) }", "out == if branch > components { out }"),
        ("promotion may drop an unrelated component charge", "decision(components + catalog, components - branch + merged, limit)", "decision(components + catalog, merged as int, limit)"),
        ("promotion may report the wrong refusal", "else { decision(components + catalog, components - branch + merged, limit) }", "else { if decision(components + catalog, components - branch + merged, limit).is_err() {out} else {Ok(())} }"),
        ("branch may admit an impossible prior charge", "out == if previous > components { Err(Refusal::AccountingOverflow) }", "out == if previous > components { out }"),
        ("over-limit growth may succeed", "else if after > limit && after > before", "else if false"),
        ("over-limit reductions may be refused", "else if after > limit && after > before", "else if after > limit"),
        ("refusal may report a different total", "used:after as u64, limit", "used:0, limit"),
    ]:
        yield (
            f"catalog quota {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/content/store/commit_candidate.rs")
    trace = Path("verification/hosted_workspace_references.rs")
    for name, old, new in [
        ("noncanonical refusal may mutate other rows", "!ObjectRecord::labels_ordered(refs@) && final(records)@ == old(records)@", "!ObjectRecord::labels_ordered(refs@)"),
        ("collision may name an identical record", "old(records)@[id] != r && #[trigger] identify.ensures((&r,),id),", "true && #[trigger] identify.ensures((&r,),id),"),
        ("success may discard another record", "&&& final(records)@ == old(records)@.insert(id,r)", "&&& true"),
        ("success may replace a different record", "&&& !old(records)@.contains_key(id) || old(records)@[id] == r", "&&& true"),
        ("success may omit the identity check", "&&& identify.ensures((&r,),id)", "&&& true"),
        ("success may stage different metadata", "&&& metadata(r,kind,version,refs@)", "&&& true"),
    ]:
        yield (
            f"metadata staging {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    trace = Path("verification/hosted_wal_writer_trace.rs")
    source = Path("crates/astrid-storage/src/engine/root_declaration.rs")
    for name, old, new in [
        ("seal may name another issuer", "out.proof_source() == IdentityProof::Engine(authority)", "out.proof_source() is Engine"),
        ("seal may change the update", "ensures out.payload() == update, out.proof_source()", "ensures true, out.proof_source()"),
        ("constructor may issue a local seal", "out.proof_source() is Untrusted,", "true,"),
        ("admission may retarget a valid batch", "update == self.payload() && match kind", "update.records == self.payload().records && match kind"),
        ("admission may exchange input rows", "update == self.payload() && match kind", "(update.principal == self.payload().principal && update.expected == self.payload().expected && update.commit == self.payload().commit) && match kind"),
        ("custody can release a foreign checkpoint", "hint.is_none() && *final(checkpoint) == *old(checkpoint)", "*final(checkpoint) == *old(checkpoint)"),
        ("custody can withhold the issuer checkpoint", "hint == *old(checkpoint) && final(checkpoint).is_none()", "final(checkpoint).is_none()"),
        ("custody failure can omit an earlier row", "forall|prior:int| 0 <= prior < i ==> #[trigger] authentic(self.payload().records@[prior],identify),", "true,"),
        ("identity failure may skip an earlier row", "forall|j:int| 0 <= j < i ==> #[trigger] authentic(self.payload().records@[j],identify),", "true,"),
    ]:
        yield (
            f"root declaration {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b),
            source if name == "identity failure may skip an earlier row" else trace,
        )
    source = Path("crates/astrid-storage/src/engine/durable/root_transition.rs")
    for name, old, new in [
        ("selection may forward unrelated rows", "p == owner && e == update.expected && rows == update.records", "p == owner && e == update.expected"),
        ("journal may rebind a selected root", "(owner,expected,root) == self.binding()", "true"),
        ("journal may hand off other bytes", "&&& encoder.ensures((&owner,expected,root),Ok(bytes))", "&&& true"),
        ("conflict may report another observed root", "a == actual && expected != a", "expected != a"),
        ("admission may select a different commit", "actual == update.expected && root.commit == update.commit", "actual == update.expected"),
        ("admission may skip a generation", "Some(old) => root.generation.value() == old.generation.value() + 1", "Some(old) => root.generation.value() > old.generation.value()"),
    ]:
        yield (
            f"durable root selection {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/kv/tree/memo_admission.rs")
    trace = Path("verification/hosted_kv_model.rs")
    for name, old, new in [
        ("purge may reuse an earlier epoch", "next as int == if", "next as int <= if"),
        ("revoked ticket can admit", "!admitted\n        }", "true\n        }"),
        ("acceptance can omit the sampled root", "else if admitted { sample.ensures((owner,),Ok(expected)) }", "else if admitted { true }"),
        ("rejection can ignore a matching root", "wrong != expected && #[trigger]", "#[trigger]"),
    ]:
        yield (
            f"KV memo {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-capsule/src/engine/wasm/native_logs/admission.rs")
    trace = Path("verification/hosted_native_log.rs")
    for name, old, new in [
        ("borrow may ignore coverage", "existing == Some(g) && covers.ensures((g,tracker,principal),true)", "existing == Some(g)"),
        ("fresh guard may ignore admission", "uncovered && begin.ensures((tracker,principal),Some(g))", "uncovered"),
        ("refusal may ignore existing guard", "None => uncovered && begin.ensures", "None => begin.ensures"),
    ]:
        yield (
            f"native log {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-storage/src/principal_directory/binding.rs")
    for name, old, new in [
        ("missing UID may invoke the callback", "None => out == Err(operation)", "None => true"),
        ("mismatched forward UID may invoke the callback", "} else { out == Err(operation) },", "} else { true },"),
        ("callback may receive another alias", "out matches Ok(r) && operation.ensures((&alias,),r)", "out.is_ok()"),
    ]:
        yield (
            f"live UID {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), trace,
        )

    source = Path("crates/astrid-core/src/platform_fs/private_projection/unix/append/selection.rs")
    for name, old, new, failure in [
        ("skips identity confirmation", "io.confirm(target,id,&file)?;", "let _ = id;", source),
        ("retries an unrelated create error", "Err(CreateError::Other(e)) => Err(e)", "Err(CreateError::Other(_)) => existing(io,target)", source),
        ("can return an unconfirmed handle", "Ok(result) => result == h && after ==", "Ok(_result) => after ==", trace),
    ]:
        yield (
            f"Unix append {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), failure,
        )

    source = Path("crates/astrid-core/src/platform_fs/windows/projection_session/append/confirmation.rs")
    for name, old, new, failure in [
        ("compares the leaf to itself", "io.volume(root)", "io.volume(&file)", source),
        ("skips the parent check", "io.directory(parent)", "io.directory(root_directory)", source),
        ("checks the parent twice", "io.directory(root_directory)", "io.directory(parent)", source),
        ("checks the directories in reverse order",
         "io.directory(parent) {\n        return Err(Failure::Native(error));\n    }\n    if let Some(error) = io.directory(root_directory)",
         "io.directory(root_directory) {\n        return Err(Failure::Native(error));\n    }\n    if let Some(error) = io.directory(parent)", source),
        ("continues after parent refusal", "return Err(Failure::Native(error));\n    }\n    if let Some(error) = io.directory(root_directory)",
         "let _ = error;\n    }\n    if let Some(error) = io.directory(root_directory)", source),
        ("can disregard successful recapture arguments", "calls == root_ok.push(Call::Recapture(*path,*root,None))",
         "calls.len() == root_ok.len() + 1", trace),
        ("can disregard failed recapture arguments", "calls == root_ok.push(Call::Recapture(*path,*root,Some(e)))",
         "calls.len() == root_ok.len() + 1", trace),
        ("recaptures with the leaf", "io.recapture(path,root)", "io.recapture(path,&file)", source),
        ("may return another handle", "accepted == file && calls == root_ok.push", "calls == root_ok.push", trace),
    ]:
        yield (
            f"Windows append {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), failure,
        )

    source = Path("crates/astrid-capsule/src/engine/wasm/native_logs/dispatch.rs")
    for name, old, new, failure in [
        ("managed write drops owner guard", "output.write(file, Some(guard), record)", "output.write(file, None, record)", source),
        ("file write may be repeated", "Destination::Explicit(file) => output.write(file, None, record),",
         "Destination::Explicit(file) => { output.write(file, None, record); output.write(file, None, record) },", source),
        ("failed file attempt skips daemon", "if policy.emit(written)", "if written && policy.emit(written)", source),
        ("absent destination permits another effect", "Destination::Absent => after == prior.push(Event::Daemon(*record))",
         "Destination::Absent => true", trace),
        ("attempt can omit or redirect fallback", "after == if !written || policy is Always { attempted.push(Event::Daemon(*record)) } else { attempted }",
         "after.len() >= attempted.len()", trace),
    ]:
        yield (
            f"guest log dispatch {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), failure,
        )

    for name, old, new, failure in [
        ("admits a different cached file", "if same(other,&file)", "if !same(other,&file)", source),
        ("refusal falls back to the supplied file", "None => Destination::Absent,", "None => Destination::Explicit(file),", source),
        ("explicit file may attempt owner admission", "f == file && after == before && match cached", "f == file && match cached", trace),
        ("matching file may return another guard", "after == before.push((*b,Some(g)))", "after.len() == before.len()+1", trace),
        ("file refusal may consult another binding", "after == before.push((*b,None))", "after.len() == before.len()+1", trace),
    ]:
        yield (
            f"warm log binding {name}", source,
            lambda s, a=old, b=new: replace_once(s, a, b), failure,
        )
