"""Downstream proof checks for canonical recovery, frame repair and physical frame validation."""

from pathlib import Path

from .common import replace_once


def consumer_defects():
    ack = Path("crates/astrid-storage/src/kv/tree/mutation_ack.rs")
    for label, clause, weaker in [
        ("unchanged result", "!changed ==> out == Ok(Some(output))", "true"),
        ("returned comparison", "value == output && publish.ensures", "publish.ensures"),
        ("accepted publication", "publish.ensures((mutations,),Ok(true))", "true"),
        ("conflict retry", "publish.ensures((mutations,),Ok(false))", "true"),
        ("failure propagation", "publish.ensures((mutations,),Err(e))", "true"),
    ]:
        yield (
            f"graph CAS acknowledgement loses {label}", ack,
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_retirement_recovery.rs"),
        )

    receipt = Path("crates/astrid-storage/src/engine/durable/group/receipt.rs")
    for label, original, weaker in [
        ("submitter binding", "final(queue)@ == old(queue)@.push(Self {transaction,receipt:*receipt,observer})", "final(queue).len() == old(queue).len()+1"),
        ("leader election", "lead == !*old(active)", "true"),
        ("leader ownership", "*final(active), lead ==", "true, lead =="),
        ("FIFO drain", "batch@ == old(queue)@", "batch.len() == old(queue).len()"),
        ("drained queue", "final(queue)@ == Seq::<Self>::empty()", "true"),
        ("successor receipt", "out == if queue.len() == 0 {None} else {Some(queue@[0].receipt)}", "out.is_some() == (queue.len() > 0)"),
        ("successor election", "*final(active) == (queue.len() > 0 && *old(active))", "true"),
        ("departing entry", "out.0 == if owns_front && old(queue).len() > 0 {Some(old(queue)@[0])} else {None}", "true"),
        ("handoff survivors", "final(queue)@ == if owns_front && old(queue).len() > 0 {old(queue)@.skip(1)} else {old(queue)@}", "true"),
        ("handoff recipient", "out.1 == if final(queue).len() > 0 {Some(final(queue)@[0].receipt)} else {None}", "true"),
        ("handoff availability", "*final(active) == (final(queue).len() > 0)", "true"),
        ("prepared receipt", "a.receipt == self.receipt && a.observer == self.observer &&", "a.observer == self.observer &&"),
        ("prepared observer", "a.receipt == self.receipt && a.observer == self.observer &&", "a.receipt == self.receipt &&"),
        ("prepared transaction", "prepare.ensures((self.transaction,&self.observer),Ok(a.prepared))", "true"),
        ("rejected receipt", "receipt == self.receipt && prepare.ensures", "prepare.ensures"),
        ("rejected transaction", "receipt == self.receipt && prepare.ensures((self.transaction,&self.observer),Err(e))", "receipt == self.receipt"),
        ("published outcome", "#[trigger] publish.ensures((self.prepared,),out) &&", "true &&"),
        ("published receipt", "final(done)@ == old(done)@.push((self.receipt,Ok(out)))", "final(done)@.len() == old(done)@.len()+1"),
        ("failed receipt", "final(done)@ == old(done)@.push((self.receipt,Err(error)))", "final(done)@.len() == old(done)@.len()+1"),
        ("first completion", "*final(self) == if notify {Self::Ready(result)} else {*old(self)}", "true"),
        ("wake eligibility", "notify == (*old(self) is Waiting || *old(self) is Promoted)", "true"),
        ("promotion", "*final(self) == if notify {Self::Promoted} else {*old(self)}", "true"),
        ("leadership wake", "notify == (*old(self) is Waiting),", "true,"),
        ("poll result", "out == match *old(self)", "true || out == match *old(self)"),
        ("terminal state", "*final(self) == if *old(self) is Ready || *old(self) is Consumed {Self::Consumed} else {Self::Waiting}", "true"),
        ("batch identity", "ensures final(sink).sent() == old(sink).sent() + batch@", "ensures final(sink).sent().len() == old(sink).sent().len() + batch.len()"),
    ]:
        yield (
            f"group receipt loses {label}", receipt,
            lambda s, a=original, b=weaker: replace_once(s, a, b), Path("verification/hosted_kv_model.rs"),
        )
    transition = Path("crates/astrid-storage/src/engine/durable/root_transition.rs")
    for label, clause in [
        ("writer map", "final(writer)@ == old(writer)@.insert(self.binding().0,self.binding().2),"),
        ("visible receipt", "visible.ensures((&self.binding().0,self.binding().2,&result.1),()),"),
        ("writer invariant", "result.0 == self.binding().2, btree_map_inv(final(writer)),"),
    ]:
        weaker = "result.0 == self.binding().2," if label == "writer invariant" else ""
        yield (
            f"root publication loses {label}", transition,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_kv_model.rs"),
        )
    declaration = Path("crates/astrid-storage/src/engine/root_declaration.rs")
    for label, clause in [
        ("sealed checkpoint origin", "make.ensures((&self.payload().principal,self.payload().commit),hint)"),
        ("untrusted checkpoint exclusion", "IdentityProof::Untrusted => *final(slot) == *old(slot)"),
    ]:
        weaker = "IdentityProof::Untrusted => true" if label.startswith("untrusted") else "true"
        yield (
            label, declaration, lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_wal_writer_trace.rs"),
        )
    recovery = Path("verification/hosted_retirement_recovery.rs")
    stage = Path("crates/astrid-storage/src/kv/tree/overlay/update.rs")
    delta = Path("crates/astrid-storage/src/kv/tree/delta_mutation.rs")
    for label, path, clause, weaker, consumer in [
        ("fallback binding", declaration, "target.binding() == (self.payload().principal,self.payload().commit)", "true", Path("verification/hosted_wal_writer_trace.rs")),
        ("fallback eligibility", declaration, "out.is_some() == (root.commit == self.binding().1)", "true", Path("verification/hosted_wal_writer_trace.rs")),
        ("fallback recipient", declaration, "publish.ensures((self.binding().0,root),result)", "true", Path("verification/hosted_wal_writer_trace.rs")),
        ("delta key", stage, "row.key@ == key@", "true", recovery),
        ("delta value", stage, "encode.ensures((&data,),Ok(slot))", "true", recovery),
        ("delta deletion", stage, "None => row.value.is_none()", "None => true", recovery),
        ("delta overlay", stage, "if q == key@ {Some(replacement)} else {lookup_spec(*old(root),q)}", "lookup_spec(*final(root),q)", recovery),
        ("delta error preservation", stage, "*final(root) == *old(root) && (replacement", "true && (replacement", recovery),
        ("delta inline bytes", delta, "&& v@ == data@", "", recovery),
        ("delta spill length", delta, "length == data.len() && spill.ensures", "spill.ensures", recovery),
        ("delta spill identity", delta, "spill.ensures((data,length),Ok(object))", "true", recovery),
    ]:
        yield (
            f"retirement storage loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), consumer,
        )
    for label, clause, weaker in [
        ("row encoding", "out.is_ok() ==> final(bytes)@ == old(bytes)@ + self.payload()", "true"),
        ("edge target", "final(refs)@.last().fields() == (label_bytes(index as u32),object,super::ReferenceKind::Owns)", "true"),
        ("edge prefix", "final(refs)@.drop_last() == old(refs)@ &&", "true &&"),
        ("parse eligibility", "out.is_ok() == valid(bytes@,*old(cursor) as int)", "true"),
        ("delete extent", "*final(cursor) as int == start+1,", "true,"),
        ("inline content", "data@ == bytes@.subrange(start+9,*final(cursor) as int)", "true"),
        ("spill length", "&& length == n,", ","),
        ("spill lookup", "==> out == Ok(refs@[i].fields().1)", "==> true"),
        ("index label", "label.value()@ == label_bytes(index as u32)", "true"),
    ]:
        yield (
            f"delta wire loses {label}", delta,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    for label, clause, weaker in [
        ("assembled key", "has_key && row.key@ == key && valid", "has_key && valid"),
        ("validator refusal", "has_key && validated(validate,key,Some(e))", "has_key"),
        ("validation before operation", "validated(validate,key,None) && !valid(bytes@,key_end)", "!valid(bytes@,key_end)"),
        ("validation before edge", "validated(validate,key,None) && valid(bytes@,key_end) && bytes@", "valid(bytes@,key_end) && bytes@"),
        ("accepted key", "&&& validated(validate,key,None)", "&&& true"),
        ("assembled inline data", "data@ == bytes@.subrange(key_end+9,finish as int)", "true"),
        ("assembled spill identity", "r.fields() == (label,object,super::ReferenceKind::Owns)", "r.fields().0 == label"),
        ("assembled spill length", "n == length && index <= u32::MAX", "index <= u32::MAX"),
    ]:
        yield (
            f"delta decoder loses {label}", delta,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    batch = Path("crates/astrid-storage/src/kv/tree/delta_batch.rs")
    for label, clause, weaker in [
        ("declared count", "rows.len() == count && exists|path", "exists|path"),
        ("contiguous extent", "rows.len() == count && exists|path", "rows.len() == count && true || exists|path"),
        ("failure position", "Err(e) => exists|rows:Seq<Mutation>", "Err(e) => true || exists|rows:Seq<Mutation>"),
        ("strict order", "out == if !ordered(rows@)", "!ordered(rows@) || out == if !ordered(rows@)"),
        ("charge limit", "out == if !ordered(rows@)", "n > delta_bytes || out == if !ordered(rows@)"),
        ("charge overflow", "out == if !ordered(rows@)", "n > u64::MAX || out == if !ordered(rows@)"),
        ("reference count", "out == if !ordered(rows@)", "expected != edges || out == if !ordered(rows@)"),
    ]:
        yield (
            f"delta batch loses {label}", batch,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    header = Path("crates/astrid-storage/src/kv/tree/delta_header.rs")
    for label, clause, weaker in [
        ("encoded fields", "final(bytes)@ == old(bytes)@ + self.wire()", "final(bytes).len() == old(bytes).len() + 36"),
        ("decoded fields", "bytes@.subrange(1,37) == h.wire()", "true"),
        ("row offset", "end == 37 && bytes@", "bytes@"),
        ("acceptance", "out.is_ok() == (bytes.len() >= 37)", "out.is_ok() ==> (bytes.len() >= 37)"),
        ("truncation", "out.is_err() ==> out == Err(ReadError::Truncated)", "true"),
    ]:
        yield (
            f"delta header loses {label}", header,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    recovery = Path("crates/astrid-storage/src/kv/tree/delta_recovery.rs")
    for label, path, clause, weaker in [
        ("predecessor output", header, "out == match reference_lookup::selected", "true || out == match reference_lookup::selected"),
        ("predecessor encoding", header, "refs@[0].fields() == (PREVIOUS@,id,super::ReferenceKind::Owns)", "true"),
        ("logical bytes", recovery, "r.totals.logical_bytes == stored.4", "true"),
        ("physical row layout", recovery, "&&& batch::layout(bytes,refs,37,bytes.len(),r.rows@,path,validate)", "&&& true"),
        ("predecessor identity", recovery, "r.previous == Some(edge.fields().1)", "r.previous.is_some()"),
        ("rejection evidence", recovery, "!(e is Truncated) ==> exists|h:", "!(e is Truncated) ==> true || exists|h:"),
        ("current charge overflow", recovery, "out == if depth != next_depth", "charge > u64::MAX || out == if depth != next_depth"),
        ("cumulative charge overflow", recovery, "out == if depth != next_depth", "prior_bytes as nat + charge > u64::MAX || out == if depth != next_depth"),
        ("predecessor contribution", recovery, "out == if depth != next_depth", "prior_bytes as nat + charge != bytes || out == if depth != next_depth"),
        ("prior depth", recovery, "out == if depth != next_depth", "depth != next_depth || out == if depth != next_depth"),
    ]:
        yield (
            f"delta recovery loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    totals = Path("crates/astrid-storage/src/kv/tree/delta_totals.rs")
    overlay = Path("crates/astrid-storage/src/kv/tree/overlay/update.rs")
    for label, path, clause, weaker in [
        ("accounting exactness", totals, "out == changed(old,key as nat", "true || out == changed(old,key as nat"),
        ("unchanged refusal", totals, "out == Err(ReplayError::Unchanged)", "true"),
        ("accounting rejection", totals, "Err(e) => out == Err(ReplayError::Accounting(e))", "Err(e) => true"),
        ("resolved key", totals, "p.key@ == key@ && p.value == value", "p.value == value"),
        ("resolved value", totals, "p.value == value && p.totals == t", "p.totals == t"),
        ("prepared totals", totals, "&& p.totals == t", ""),
        ("installed totals", overlay, "ensures *final(totals) == change.totals", "ensures true"),
        ("unrelated overlay keys", overlay, "Some(change.value)} else {lookup_spec(*old(root),q)}", "Some(change.value)} else {lookup_spec(*final(root),q)}"),
    ]:
        yield (
            f"replay application loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    spill = Path("crates/astrid-storage/src/kv/tree/spill_record.rs")
    for label, clause, weaker in [
        ("opaque writer bytes", "r.contents() == (ObjectKind::KvLeaf,version.number(),data@", "true || r.contents() == (ObjectKind::KvLeaf,version.number(),data@"),
        ("owning file", "fields.3[0].fields() == (CONTENT@,file,super::ReferenceKind::Owns)", "true"),
        ("reference refusal", "out == if !(r.0 is KvLeaf)", "r.3[0].fields().2 != super::ReferenceKind::Owns || out == if !(r.0 is KvLeaf)"),
        ("file identity", "else {Ok(r.3[0].fields().1)}", "else {out}"),
        ("inline bytes", "out matches Ok(v) && v@ == data@", "out.is_ok()"),
        ("loaded bytes", "valid_payload(&r,plain,length) && v@ == r.contents().2", "valid_payload(&r,plain,length)"),
        ("load error", "load.ensures((object,),Err(e)) ||", "true || load.ensures((object,),Err(e)) ||"),
        ("invalid spill identity", "id == object &&", "true &&"),
        ("chunk callback", "chunk.ensures((object,length,&r),Ok(v))", "true"),
    ]:
        yield (
            f"spill recovery loses {label}", spill,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_spill_record.rs"),
        )
    for label, path, clause, weaker in [
        ("writer admission", totals, "out == if unchanged ||", "true || out == if unchanged ||"),
        ("applied totals", overlay, "out.is_ok() && totals == t &&", "out.is_ok() &&"),
        ("overlay occupancy", overlay, "if prior == next {out == Err(ApplyError", "if found.is_some() {true} else if prior == next {out == Err(ApplyError"),
        ("fallback error provenance", overlay, "&& load.ensures((&row.key,&row.value,found.is_none()),Err(e))", ""),
        ("atomic error", overlay, "after == initial && totals == old_totals && load.ensures", "load.ensures"),
    ]:
        yield (
            f"addressed replay loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_mutation.rs"),
        )
    chain = Path("crates/astrid-storage/src/kv/tree/delta_chain.rs")
    for label, clause, weaker in [
        ("per-index owner read", "ids(steps).no_duplicates(), step_read(owner,steps,end,read,i),", "ids(steps).no_duplicates(),"),
        ("checkpoint endpoint", "&&\n            read.ensures((owner,id),Ok(Head::Checkpoint {tree:c.tree,totals:c.totals}))", ""),
        ("genesis totals", "c.tree.is_none() && zero(c.totals)", "c.tree.is_none()"),
        ("head origin", "if steps.len() == 0 {next == Some(head)}", "if steps.len() == 0 {true}"),
        ("source failure", "&& read.ensures((owner,id),Err(cause))", ""),
        ("cycle address", "k == id && ids(steps).contains(id)", "ids(steps).contains(id)"),
        ("complete linked path", "follows(owner,head,c.newest_first@,end,read) && match end", "true && match end"),
    ]:
        yield (
            f"delta chain loses {label}", chain,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_chain.rs"),
        )
    source = Path("crates/astrid-storage/src/kv/tree/record_source.rs")
    record = Path("crates/astrid-storage/src/storage_model/object_record.rs")
    for label, path, clause, weaker in [
        ("staged contents", source, "out matches Ok(t) && copy.ensures((&staged@[id],),t)", "out is Ok"),
        ("engine value", source, "Ok(t) => engine.ensures((owner,id),Ok(Some(t)))", "Ok(t) => true"),
        ("missing address", source, "k == id && engine.ensures", "engine.ensures"),
        ("engine error", source, "Err(Error::Source(e)) => engine.ensures((owner,id),Err(e))", "Err(Error::Source(e)) => true"),
        ("canonical payload", record, "a.2 == b.2 && a.4", "a.4"),
        ("logical size", record, "a.4 == b.4 && a.5", "a.5"),
        ("reference sequence", record, "a.3.len() == b.3.len()", "true"),
        ("reference fields", record, "(#[trigger] a.3[i]).fields() == (#[trigger] b.3[i]).fields()", "(#[trigger] a.3[i]).fields().1 == (#[trigger] b.3[i]).fields().1"),
    ]:
        yield (
            f"staged record source loses {label}", path,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_record_source.rs"),
        )
    batch = Path("crates/astrid-storage/src/kv/tree/overlay/batch.rs")
    for label, clause, weaker in [
        ("initial context", "&& states[0]==initial", ""),
        ("all successful mutations", "Ok(s) => h.len()==rows.len()+1 && h.last()==s", "Ok(s) => h.last()==s"),
        ("failure position", "i<rows.len() && h.len()==i+1 && transition", "i<rows.len() && transition"),
        ("containing object", "k==id && match e", "match e"),
        ("successful checkpoint resolution", "&&& replay_values::resolved(before.0,tree,&row.key,", "&&& true || replay_values::resolved(before.0,tree,&row.key,"),
        ("installed overlay", "&&& update::changed(before.1,next.1,row,before.2,next.2,pair,Ok(()))", "&&& true"),
        ("refused lookup", "ApplyError::Load(e) => replay_values::resolved", "ApplyError::Load(e) => true || replay_values::resolved"),
        ("refused change", "&& update::changed(before.1,before.1,row,before.2,before.2,p,Err(e))", "&& true"),
    ]:
        yield (
            f"addressed batch replay loses {label}", batch,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_overlay_batch.rs"),
        )
    graph = Path("crates/astrid-storage/src/ownership/graph_read.rs")
    for label, clause, weaker in [
        ("storage refusal", "Err(e) => out==Err(e),", "Err(e) => out.is_err(),"),
        ("missing input", "None=>missing.ensures((),g)", "None=>true"),
        ("decoded graph", "Some(bytes)=>decode.ensures((bytes,),Ok(g))", "Some(bytes)=>true"),
        ("validation", "selected(raw,missing,decode,g) && validate.ensures((&g,),Ok(()))", "selected(raw,missing,decode,g)"),
        ("decoder refusal", "raw matches Some(bytes) && decode.ensures((bytes,),Err(e))", "raw.is_some()"),
        ("validation refusal", "selected(raw,missing,decode,g) && validate.ensures((&g,),Err(e))", "selected(raw,missing,decode,g)"),
    ]:
        yield (
            f"startup graph admission loses {label}", graph,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_retirement_recovery.rs"),
        )
    reservations = Path("crates/astrid-storage/src/ownership/reservation_validation.rs")
    for label, clause, weaker in [
        ("retired owner exclusion", "rows@.contains_key(k) ==> !owners@.contains_key(k) &&", "rows@.contains_key(k) ==> true &&"),
        ("existing fleet", "(rows@[k].fleet matches Some(f) ==> fleets@.contains_key(f)))", "true)"),
        ("unique retained name", "named(rows@,j,n,name) ==> i==j", "named(rows@,j,n,name) ==> true"),
        ("missing fleet refusal", "Err(Error::Fleet(f)) => !fleets@.contains_key(f) &&", "Err(Error::Fleet(f)) => true &&"),
        ("owned generation refusal", "rows@.contains_key(k) && owners@.contains_key(k),", "rows@.contains_key(k),"),
        ("duplicate identities", "Err(Error::Alias(n,i,j)) => i!=j &&", "Err(Error::Alias(n,i,j)) => true &&"),
    ]:
        yield (
            f"retirement reservation validation loses {label}", reservations,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_retirement_recovery.rs"),
        )
    mutations = Path("crates/astrid-storage/src/kv/tree/mutation_replay.rs")
    for label, clause, weaker in [
        ("initial state", "states[0] == initial", "true"),
        ("encoded mutation", "f.ensures(((#[trigger] states[i]),tree,id,&rows[i]),Ok(states[i+1]))", "f.ensures(((#[trigger] states[i]),tree,id,&rows[i]),Ok(states[i+1])) || f.ensures((states[i],tree,id,&rows[0]),Ok(states[i+1]))"),
        ("last state", "states.len() == rows.len()+1 && states.last() == s", "states.len() == rows.len()+1"),
        ("all mutations", "states.len() == rows.len()+1 && states.last() == s", "states.last() == s"),
        ("failing mutation", "apply.ensures((states.last(),tree,id,&rows@[states.len()-1]),Err(e))", "true"),
    ]:
        yield (
            f"ordered mutation replay loses {label}", mutations,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_replay_values.rs"),
        )
    reader = Path("crates/astrid-storage/src/engine/durable/read_admission.rs")
    for label, clause, weaker in [
        ("stale retry", "Ok(None) => self.generation != expected,", "Ok(None) => true,"),
        ("matching generation", "Ok(Some(r)) => self.generation == expected && decode.", "Ok(Some(r)) => decode."),
        ("indexed read", "decode.ensures((&self.file,id,location),Ok(r))", "true"),
        ("indexed error", "decode.ensures((&self.file,id,location),Err(e))", "true"),
    ]:
        yield (
            f"generation-bound reader loses {label}", reader,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_batch_slots.rs"),
        )
    source = Path("crates/astrid-storage/src/engine/durable/wal/overlay_object.rs")
    for label, clause, weaker in [
        ("address", "ensures s.id == id,s.generation == generation,", "ensures s.generation == generation,"),
        ("generation", "ensures s.id == id,s.generation == generation,", "ensures s.id == id,"),
        ("arena placement", "s.location == (if index@.contains_key(id) {Some(index@[id])} else {None}),", "s.location.is_some() == index@.contains_key(id),"),
        ("WAL contents", " && r.same_contents(&*objects@[id].record)", ""),
        ("WAL presence", "None => !objects@.contains_key(id),", "None => true,"),
    ]:
        yield (
            f"locked object snapshot loses {label}", source,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_batch_slots.rs"),
        )
    cache = Path("crates/astrid-storage/src/kv/tree/checkpoint_cache.rs")
    for label, clause, weaker in [
        ("hit contents", "image(final(self).contents()[id]) == image(h)", "true"),
        ("hit availability", "final(self).contents() == old(self).contents() && out.is_ok()", "final(self).contents() == old(self).contents()"),
        ("decoded source", "record::parsed(&r,h.node,validate) && r.contents().1 == version.number()", "r.contents().1 == version.number()"),
        ("source format", "record::parsed(&r,h.node,validate) && r.contents().1 == version.number()", "record::parsed(&r,h.node,validate)"),
        ("decode refusal", "&& record::refusal(&r,validate,e),", "&& true,"),
        ("source refusal", "&& load.ensures((old(self).owner(),id),Err(e))", "&& true"),
        ("initial contents", "c.contents() == Map::<ObjectId,Loaded>::empty(),", "true,"),
        ("owner binding", "c.owner() == principal,", "true,"),
        ("canonical hit", "out matches Ok(h) ==> h.object == id && record::ordered(h.node) &&", "out matches Ok(h) ==> h.object == id &&"),
    ]:
        yield (
            f"decoded cache loses {label}", cache,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_checkpoint_leaf_record.rs"),
        )
    descent = Path("crates/astrid-storage/src/kv/tree/checkpoint_descent.rs")
    for label, clause, weaker in [
        ("scheduled root", "== (initial,Page::Root(root))", "== (if path.len()==0 {at} else {path[0].0})"),
        ("child identity", "to == Page::Child(rows@[i])", "to is Child"),
        ("level decrement", "child.level as nat+1 == level &&", "true &&"),
        ("leaf result", "&& slot(rows@,key,v)", "&& true"),
        ("load refusal", "Err(Error::Source(e)) => read.ensures((at.0,id(at.1)),Err(e))", "Err(Error::Source(e)) => true"),
        ("refused branch address", "Err(Error::Branch(k)) => k == id(at.1) && exists", "Err(Error::Branch(k)) => exists"),
    ]:
        yield (
            f"point descent loses {label}", descent,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_checkpoint_descent.rs"),
        )
    yield (
        "point descent loses loaded root identity", Path("crates/astrid-storage/src/kv/tree/checkpoint_page.rs"),
        lambda s: replace_once(s, "Page::Root(id) => id == handle.object", "Page::Root(_) => true"),
        Path("verification/hosted_checkpoint_page.rs"),
    )
    for label, clause, weaker in [
        ("authenticated handle", "checkpoint_page::agrees(at.1,handle) && handle.node.contents() == body", "handle.node.contents() == body"),
        ("mismatch address", "Err(Error::Mismatch(k)) => k == id(at.1) && exists", "Err(Error::Mismatch(k)) => exists"),
        ("mismatch evidence", "&& !checkpoint_page::agrees(at.1,h)", ""),
    ]:
        yield (
            f"point descent loses {label}", descent,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_checkpoint_descent.rs"),
        )
    point = Path("crates/astrid-storage/src/kv/tree/checkpoint_point.rs")
    for label, clause, weaker in [
        ("raw selected index", "index == self::index(children@,key@),", "true,"),
        ("hit key", "(#[trigger] input@[i]).key@ == key@ && input@[i].value == v", "(#[trigger] input@[i]).value == v"),
        ("hit slot", "(#[trigger] input@[i]).key@ == key@ && input@[i].value == v", "(#[trigger] input@[i]).key@ == key@"),
        ("canonical membership", "(#[trigger] input@[i]).key@ == key@ ==> out == Some(input@[i].value)", "(#[trigger] input@[i]).key@ == key@ ==> true"),
        ("lower fence", "index > 0 ==>\n                !encoding::below(key@,(#[trigger] children@[i]).lower_bound@)", "index > 0 ==> children@[i].level == (#[trigger] children@[i]).level"),
        ("upper fence", "encoding::below(key@,(#[trigger] children@[i]).lower_bound@)\n        },", "(#[trigger] children@[i]).level == children@[i].level\n        },"),
    ]:
        yield (
            f"checkpoint point lookup loses {label}", point,
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_checkpoint_point.rs"),
        )
    values = Path("crates/astrid-storage/src/kv/tree/replay_values.rs")
    for label, clause, weaker in [
        ("prior bytes", "pair.0 == prior && replacement", "replacement"),
        ("deletion", "None => out == Ok(None)", "None => true"),
        ("value resolution", "Ok(Some(bytes)) => value.ensures((context,v),Ok(bytes))", "Ok(Some(bytes)) => true"),
        ("value failure", "Err(e) => value.ensures((context,v),Err(e))", "Err(e) => true"),
        ("lookup failure", "out matches Err(e) && lookup.ensures((context,tree,key),Err(e))", "out is Err"),
        ("overlay hit", "else {after_prior(context,None,slot,value,out)}", "else {true}"),
    ]:
        yield (
            f"replay value resolution loses {label}", values,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_replay_values.rs"),
        )
    fold = Path("crates/astrid-storage/src/kv/tree/delta_replay.rs")
    for label, clause, weaker in [
        ("success history", "out matches Ok(c) ==> replayed(initial,base,tree,input@,0,apply,c)", "out matches Ok(c) ==> true"),
        ("error prefix", "out matches Err(e) ==> failed(initial,base,tree,input@,apply,e)", "out matches Err(e) ==> true"),
        ("final depth", "end.depth == row.depth && end.bytes", "end.bytes"),
        ("final bytes", "end.bytes == row.delta_bytes && end.totals", "end.totals"),
        ("totals agreement", "end.totals == row.totals", "true"),
        ("counter admission", "&&& counter(prior,row).is_none()", "&&& true"),
        ("mutation result", "&&& apply.ensures((prior.state,tree,row.object,&row.mutations,prior.totals),Ok((end.state,end.totals)))", "&&& true"),
        ("counter refusal address", "id == row.object && counter(prior,row) == Some(c)", "counter(prior,row) == Some(c)"),
        ("apply refusal", "apply.ensures(args,Err(e))", "true"),
        ("totals refusal address", "Error::Totals(id) => id == row.object &&", "Error::Totals(id) =>"),
    ]:
        yield (
            f"chronological replay loses {label}", fold,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_delta_replay.rs"),
        )
    checkpoint = Path("crates/astrid-storage/src/kv/tree/checkpoint_replay.rs")
    for label, clause, weaker in [
        ("root refusal", "(out is Err && out->Err_0 is Root) == (chain.tree != root)", "chain.tree != root ==> (out is Err && out->Err_0 is Root)"),
        ("accounting refusal", "(out is Err && out->Err_0 is Totals) == (chain.tree == root && measured != chain.totals)", "chain.tree == root && measured != chain.totals ==> (out is Err && out->Err_0 is Totals)"),
        ("initial state", "out matches Ok(c) ==> exists|s:S| #[trigger] start.ensures((),s) &&", "out matches Ok(c) ==> exists|s:S|"),
        ("application failure history", "delta_replay::failed(s,measured,root,chain.newest_first@,apply,e)", "true"),
    ]:
        yield (
            f"checkpoint replay loses {label}", checkpoint,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_projection_record.rs"),
        )
    envelope = Path("crates/astrid-storage/src/kv/tree/projection_record.rs")
    for label, clause, weaker, target in [
        ("checkpoint physical bytes", "f.2 == checkpoint_bytes(totals) && f.4", "f.4", "hosted_projection_record"),
        ("checkpoint root", "f.3[0].fields() == (label@,id,super::ReferenceKind::Owns)", "true", "hosted_projection_record"),
        ("type refusal", "{out == Err(Error::Type)}", "{true}", "hosted_projection_record"),
        ("unknown tag", "else {out == Err(Error::Tag)}", "else {true}", "hosted_projection_record"),
        ("checkpoint trailing", "bytes.len() > 17 {out == Err(Error::Trailing)}", "bytes.len() > 17 {true}", "hosted_projection_record"),
        ("load source", "=> load.ensures((owner,id),Err(e))", "=> true", "hosted_projection_record"),
        ("decoded load", "valid(&*r,version,label,check,Ok(h))", "true", "hosted_projection_record"),
        ("delta contents", "#[trigger] delta::admitted(record,check,r,b,refs,p)", "true || #[trigger] delta::admitted(record,check,r,b,refs,p)", "hosted_delta_mutation"),
    ]:
        yield (
            f"projection envelope loses {label}", envelope,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path(f"verification/{target}.rs"),
        )
    materializer = Path("crates/astrid-storage/src/engine/durable/closure_load.rs")
    for label, clause, weaker in [
        ("commit admission", "rows@[i].1.contents().0 is Commit,", "true,"),
        ("reported kind", "rows@[i].1.contents().0 == kind,", "true,"),
        ("root absence", "Err(CommitError::Missing) => forall|i:int| 0 <= i < rows.len() ==> #[trigger] rows@[i].0 != root", "Err(CommitError::Missing) => true"),
        ("row order", "&&& in_id_order(row_ids(rows@))", "&&& true"),
        ("root membership", "&&& walk::closed(root,Set::empty(),graph,ids)", "&&& true"),
        ("minimality", "==> ids.subset_of(nodes)", "==> true"),
        ("acyclicity", "rank.dom() == ids && #[trigger] walk::ranked(graph,Set::empty(),rank)", "rank.dom() == ids"),
        ("record contents", "(#[trigger] rows@[i]).1.contents() == table@[rows@[i].0].contents()\n", "true\n"),
        ("missing identity", "id == e && !table@.contains_key(id)", "!table@.contains_key(id)"),
        ("cycle evidence", "=> walk::reaches(Preload(table).edges(),Set::empty(),id,id) &&", "=> true &&"),
    ]:
        yield (
            f"recovery materializer loses {label}", materializer,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_closure_model.rs"),
        )
    append = Path("crates/astrid-storage/src/engine/durable/arena_frame.rs")
    readback = Path("verification/hosted_arena_append.rs")
    closure = Path("crates/astrid-storage/src/engine/durable/recovered_closure.rs")
    for label, clause, weaker in [
        ("load binding", "Ok(()) => exists|rows:Vec<(K,R)>| #[trigger] load.ensures((commit,offset),Ok(rows)) &&", "Ok(()) => exists|rows:Vec<(K,R)>|"),
        ("validation binding", "validate.ensures((&rows,commit,offset),Ok(())) &&", "true &&"),
        ("accepted IDs", "final(known)@ == old(known)@.union(ids(rows@))", "true"),
        ("failed collection", "Err(e) => final(known)@ == old(known)@ &&", "Err(e) =>"),
        ("load error", "load.ensures((commit,offset),Err(e)) ||", "true ||"),
        ("validation error", "&& validate.ensures((&rows,commit,offset),Err(e))", "&& true"),
    ]:
        yield (
            f"recovered closure loses {label}", closure,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_recovery_barrier.rs"),
        )
    for label, clause, weaker in [
        ("owner coverage", "entries.to_set() == history@.kv_pairs() && entries.len() == history.len() &&", "entries.len() == history.len() &&"),
        ("owner validation", "forall|i:int| 0 <= i < entries.len() ==> #[trigger] accepted(entries[i].1,sets[i],load,validate)", "true"),
        ("object coverage", "known.contains(k) == #[trigger] recorded(sets,k)", "known.contains(k) ==> #[trigger] recorded(sets,k)"),
        ("object origin", "known.contains(k) == #[trigger] recorded(sets,k)", "known.contains(k) <== #[trigger] recorded(sets,k)"),
        ("error origin", "Err(e) => exists|p:P| #[trigger] history@.contains_key(p)", "Err(e) => true || exists|p:P| #[trigger] history@.contains_key(p)"),
    ]:
        yield (
            f"recovered closure loses {label}", closure,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_recovery_barrier.rs"),
        )
    barrier = Path("crates/astrid-storage/src/engine/durable/recovery_barrier.rs")
    for label, clause, weaker in [
        ("WAL identity", "stable.wal() == wal", "true"),
        ("handoff result", "ensures finish.ensures((self.wal(),),value)", "ensures true"),
        ("represented order", "final(files).calls() == all && final(files).durable() == both.insert", "final(files).durable() == both.insert"),
        ("unrepresented order", "final(files).calls() == roots && final(files).durable() == both", "final(files).durable() == both"),
        ("represented images", "final(files).durable() == both.insert(x,old(files).pending()[x])", "true"),
        ("unrepresented images", "final(files).durable() == both}", "true}"),
        ("arena failure", "Err(Error::Arena(_)) => final(files).calls() == arena", "Err(Error::Arena(_)) => true"),
        ("roots failure", "Err(Error::Roots(_)) => final(files).calls() == roots", "Err(Error::Roots(_)) => true"),
        ("representations failure", "old(files).has_representations() && final(files).calls() == all", "true"),
    ]:
        yield (
            f"recovery barrier loses {label}", barrier,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), Path("verification/hosted_recovery_barrier.rs"),
        )
    repair = Path("crates/astrid-storage/src/engine/durable/frame_repair.rs")
    for label, clause, weaker in [
        ("committed protection", "w.protected == end && w.restore_cursor", "w.restore_cursor"),
        ("live protection", "w.protected == p && !w.restore_cursor", "!w.restore_cursor"),
        ("complete end", "n == next && offset < n", "offset < n"),
        ("oversize interior", "interior == (next <= end)", "true"),
        ("reject evidence", "(blocked || (probe && old(media).probe_result(offset,Ok(true))))", "true"),
        ("probe finding", "(probe ==> old(media).probe_result(offset,Ok(false)))", "true"),
        ("protected cutoff", "_ => !blocked &&", "_ => true &&"),
        ("resize failure", "Err(Error::Resize(_)) => final(media).calls() == prefix.push(Event::Resize(offset))", "Err(Error::Resize(_)) => true"),
        ("flush ordering", "_ => final(media).calls() == prefix.push(Event::Resize(offset)).push(Event::Flush)", "_ => true"),
        ("retained prefix", "final(media).bytes() == old(media).bytes().take(offset as int) &&", "true &&"),
        ("durable prefix", "final(media).durable() == final(media).bytes()", "true"),
    ]:
        yield (
            f"frame repair loses {label}", repair,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), readback,
        )

    for label, clause, weaker in [
        ("frame domain", "ok == (bytes@.take(8) == magic@)", "true"),
        ("version refusal", "(out matches Err(HeaderError::Version)) == !current", "(out matches Err(HeaderError::Version)) ==> !current"),
        ("reserved bits", "(out matches Err(HeaderError::Reserved)) == (current && !clear)", "(out matches Err(HeaderError::Reserved)) ==> (current && !clear)"),
        ("declared length", "h.payload_len == vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(12,20))", "true"),
        ("saved checksum", "h.checksum@ == bytes@.subrange(20,52)", "true"),
        ("payload length", "(out matches Err(PayloadError::Length)) == (payload.len() != header.payload_len)", "(out matches Err(PayloadError::Length)) ==> (payload.len() != header.payload_len)"),
        ("accepted digest", "sum == header.checksum && hash.ensures", "hash.ensures"),
        ("hash arguments", "sum == header.checksum && hash.ensures((magic,header.payload_len,payload),sum)", "sum == header.checksum"),
        ("checksum refusal", "sum != header.checksum &&", "true &&"),
    ]:
        yield (
            f"physical frame loses {label}", append,
            lambda s, a=clause, b=weaker: replace_once(s, a, b), readback,
        )
