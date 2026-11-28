"""Downstream proof checks for canonical recovery, frame repair and physical frame validation."""

from pathlib import Path

from .common import replace_once


def consumer_defects():
    receipt = Path("crates/astrid-storage/src/engine/durable/group/receipt.rs")
    for label, original, weaker in [
        ("submitter binding", "final(queue)@ == old(queue)@.push(Self {transaction,receipt:*receipt,observer})", "final(queue).len() == old(queue).len()+1"),
        ("leader election", "lead == !*old(active)", "true"),
        ("leader ownership", "*final(active), lead ==", "true, lead =="),
        ("FIFO drain", "batch@ == old(queue)@", "batch.len() == old(queue).len()"),
        ("drained queue", "final(queue)@ == Seq::<Self>::empty()", "true"),
        ("successor receipt", "out == if queue.len() == 0 {None} else {Some(queue@[0].receipt)}", "out.is_some() == (queue.len() > 0)"),
        ("successor election", "*final(active) == (queue.len() > 0 && *old(active))", "true"),
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
