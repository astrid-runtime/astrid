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
    for label, before, after in [
        ("physical predecessor", "edge.fields().1==next && edge.fields().2==ReferenceKind::Owns", "edge.fields().2==ReferenceKind::Owns"),
        ("row key", "as int))!=address", "as int))==address"),
        ("delete width", "if bytes[tag]==delta::DELETE {tag+1}", "if bytes[tag]==delta::DELETE {tag+2}"),
        ("spilled length width", "} else {tag+9}", "} else {tag+8}"),
        ("inline payload width", "tag+9+crate::checkpoint_value::value_length(bytes,tag+1)", "tag+9"),
    ]:
        yield (
            f"physical marker history loses {label}", marker,
            lambda s, a=before, b=after: replace_once(s, a, b), marker,
        )
    for label, source, before, after in [
        ("owner", graph, "g.owner==*owner && loaded.history@", "loaded.history@"),
        ("component", admission, "if !component.same(&newest) {return None;}", ""),
        ("decision", admission, "Some((graph.root,result))", "Some((graph.root,Ok(Admission::Allowed)))"),
    ]:
        yield (
            f"retained owner marker loses {label}", source,
            lambda s, a=before, b=after: replace_once(s, a, b), admission,
        )
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
        ("canonical delta", marker, "marker_bytes(out.0.contents().2,key@), out.1", "true, out.1", append),
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

    pruning = Path("crates/astrid-storage/src/storage_model/staged_closure.rs")
    for label, before, after in [
        ("commit root", "let mut stack=vec![root];", "let mut stack=vec![ObjectId::new([0;32])];"),
        ("owning target", "stack.push(child);", "stack.push(ObjectId::new([0;32]));"),
        ("declaration order", "rows.as_mut_slice().sort_unstable_by_key(key);", ""),
        ("retained declarations", "    rows\n}", "    Vec::new()\n}"),
    ]:
        yield (
            f"transaction pruning loses {label}", pruning,
            lambda s, a=before, b=after: replace_once(s, a, b), pruning,
        )
    declaration = Path("crates/astrid-storage/src/engine/root_declaration.rs")
    for label, before, after in [
        ("staged records", "staged_closure::select(staged,commit)", "staged_closure::select(BTreeMap::new(),commit)"),
        ("expected root", "Some(a)=>Self::sealed(Update {principal,expected,commit,records},a)", "Some(a)=>Self::sealed(Update {principal,expected:None,commit,records},a)"),
        ("session seal", "Some(a)=>Self::sealed(Update {principal,expected,commit,records},a)", "Some(_)=>Self::untrusted(principal,expected,commit,records)"),
    ]:
        yield (
            f"writer declaration loses {label}", declaration,
            lambda s, a=before, b=after: replace_once(s, a, b), declaration,
        )
    header_writer = Path("crates/astrid-storage/src/storage_model/header_writer.rs")
    for label, before, after in [
        ("state destination", "commit(commit_refs,prior,sid,v)", "commit(commit_refs,prior,head,v)"),
        ("parent", "commit(commit_refs,prior,sid,v)", "commit(commit_refs,None,sid,v)"),
        ("commit identity", "            Ok(t)\n", "            Ok((t.0,sid))\n"),
    ]:
        yield (
            f"staged publication loses {label}", header_writer,
            lambda s, a=before, b=after: replace_once(s, a, b), header_writer,
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

    merge_rows = Path("crates/astrid-storage/src/engine/durable/wal/merge_rows.rs")
    for label, before, after in [
        ("lower prepared identity", "Ordering::Greater=>Row::Prepared(*j,frame)", "Ordering::Greater=>Row::Prepared(*i,frame)"),
        ("overlapping record", "Ordering::Equal=>Row::Both(*i,record,frame)", "Ordering::Equal=>Row::Prepared(*j,frame)"),
        ("decoded payload", "if &decoded==record", "if &decoded!=record"),
    ]:
        yield (
            f"WAL input merge loses {label}", merge_rows,
            lambda s, a=before, b=after: replace_once(s, a, b), merge_rows,
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

    named_batch = Path("verification/hosted_wal_prepared_batch.rs")
    for label, source, clause, weakness, consumer in [
        ("tagged identity", Path("crates/astrid-storage/src/engine/durable/format/verified_record.rs"),
         "ensures yes==declared(bytes@,scheme,id),", "ensures true,", named_batch),
        ("object order", Path("crates/astrid-storage/src/storage_model/object_reference.rs"),
         "ensures yes==match previous {None=>true,Some(p)=>Self::digest_before(p.digest(),self.digest())},", "ensures true,", named_batch),
        ("full declaration set", publication, "out matches Ok(rows) ==> canonical_rows(g,rows@,scheme),", "out matches Ok(rows) ==> rows.len()==g.records.len(),", named_batch),
        ("stored encoding", named_batch, "payload is Lz4 && payload.bytes()==vstd::bytes::spec_u64_to_le_bytes(canonical.len() as u64)+compression(canonical)", "payload is Lz4", named_batch),
        ("closure refusal", publication, "out matches Err(crate::closure_walk::Failure::Source(k,e)) ==> k==e && !table@.contains_key(k),",
         "out matches Err(crate::closure_walk::Failure::Source(k,e)) ==> k==e,", named_batch),
        ("selected root payload", named_batch, "parse_written(&r.roots[0].body,&name,scheme,expected,replacement)",
         "parse_written(begin,&name,scheme,expected,replacement)", named_batch),
    ]:
        yield (
            f"fresh declaration batch loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    for label, clause, weakness in [
        ("captured plain body", "capture.body.as_slice()", "&capture.body[..0]"),
        ("decoded reference edges", "table.insert(key,record);", "if record.references().is_empty() {table.insert(key,record);}"),
        ("recovered table domain", "while i<p.group.objects.len()", "while i<p.group.objects.len() && i<1"),
        ("decoded identity", "table.insert(key,record);", "table.insert(ObjectId::new([0;32]),record);"),
    ]:
        yield (
            f"fresh table recovery loses {label}", named_batch,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), named_batch,
        )

    for label, source, clause, weakness, consumer in [
        ("WAL root", named_batch, "let root=p.journal.replacement.commit;",
         "let root=ObjectId::new([0;32]);", named_batch),
        ("walk refusal", named_batch, "Ok(rows)=>rows,Err(e)=>return Err(RecoveryError::Closure(receipt.flush,e)),",
         "Ok(rows)=>rows,Err(_)=>return Ok((table,receipt)),", named_batch),
        ("owning path", publication, "owning_child(decoded.contents().3,i);",
         "owning_child(source.contents().3,i);", publication),
        ("acyclicity", publication, "rank.dom()==ids && #[trigger] crate::closure_walk::ranked(",
         "rank.dom().subset_of(ids) && #[trigger] crate::closure_walk::ranked(", named_batch),
    ]:
        yield (
            f"recovered publication walk loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    reader = Path("verification/hosted_record_roundtrip.rs")
    for label, clause, weakness in [
        ("scanner key", "Ok((key,decoded)) => key==id && same_fields(decoded,*source),",
         "Ok((_,decoded)) => same_fields(decoded,*source),"),
        ("decoded fields", "Ok((key,decoded)) => key==id && same_fields(decoded,*source),",
         "Ok((key,_)) => key==id,"),
    ]:
        yield (
            f"cold table recovery loses {label}", reader,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), named_batch,
        )

    arena_batch = Path("verification/hosted_wal_recovered_arena.rs")
    for label, source, clause, weakness, consumer in [
        ("canonical body", named_batch, "payload.extend_from_slice(bytes);",
         "payload.extend_from_slice(&bytes[..0]);", named_batch),
        ("arena location", arena_batch, "index.insert(rows[i].0,loc);",
         "index.insert(rows[i].0,locations[0]);", arena_batch),
        ("arena header", arena_batch,
         "frame::append_batch(arena,rows,payload_of,hash,frame::ARENA_MAGIC",
         "frame::append_batch(arena,rows,payload_of,hash,frame::ROOT_MAGIC", arena_batch),
        ("physical contents", arena_batch, "arena_entry(index@[row.0],row.1@,final(arena).image(),old(arena).image().len())",
         "index@[row.0].payload_len==row.1.len()", named_batch),
    ]:
        yield (
            f"recovered arena batch loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    sync_source = Path("crates/astrid-storage/src/engine/durable/arena_frame.rs")
    for label, source, clause, weakness, consumer in [
        ("volume receipt", Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
         "Self::Volume(region)=>Ok(JournalFlush::AwaitingContainer(capture(region)))",
         "Self::Volume(_)=>Ok(JournalFlush::StableFile)", Path("crates/astrid-storage/src/engine/durable/frontier.rs")),
        ("required flush", sync_source, "let flush=file.sync_replayed()?;", "let flush=JournalFlush::StableFile;", sync_source),
        ("stable image", sync_source,
         "v@==locations@ && (flush is StableFile ==> final(file).stable()==old(file).image())",
         "v@==locations@", arena_batch),
        ("release on success", arena_batch,
         "Ok(locations)=>locations,Err(e)=>return Err(ArenaError::Sync(e)),",
         "Ok(locations)=>locations,Err(_)=>(Vec::new(),crate::frontier::JournalFlush::StableFile),", arena_batch),
    ]:
        yield (
            f"arena sync loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    reopen = Path("verification/hosted_wal_arena_reopen.rs")
    for label, source, clause, weakness, consumer in [
        ("physical address", reopen, "io::with_span(media,loc.offset,size,consume)",
         "io::with_span(media,0,size,consume)", reopen),
        ("reference identity", reopen, "let result=indexed::read(data,base,loc,id,",
         "let result=indexed::read(data,base,loc,ObjectId::new([0;32]),", reopen),
        ("complete index", reopen, "table.insert(*id,record);",
         "if record.references().is_empty() {table.insert(*id,record);}", reopen),
        ("confirmed checksum", arena_batch,
         "crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,row.1@,index@[row.0].checksum)",
         "index@[row.0].payload_len==row.1.len()", named_batch),
        ("container decision", reopen,
         "if let crate::frontier::JournalFlush::AwaitingContainer(())=flush",
         "if let crate::frontier::JournalFlush::StableFile=flush", reopen),
        ("known set", reopen, "ColdRead::Loaded(media,table,known)",
         "ColdRead::Loaded(media,table,std::collections::BTreeSet::new())", reopen),
    ]:
        yield (
            f"cold native reread loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    repair = Path("crates/astrid-storage/src/engine/durable/frame_repair.rs")
    for label, source, clause, weakness in [
        ("frame cursor", reopen, "at=f.end;", "at=end;"),
        ("wire-derived index", reopen, "    Ok(index)\n}", "    Ok(BTreeMap::new())\n}"),
        ("frame magic", repair, "if !frame::magic_matches(&h,magic)", "if false && !frame::magic_matches(&h,magic)"),
        ("current frame offset", reopen, "index_fresh(&mut index,at,body", "index_fresh(&mut index,start,body"),
        ("gapless extent", arena_batch, "index.insert(rows[i].0,loc);", "if i>0 {index.insert(rows[i].0,loc);}"),
    ]:
        yield (
            f"cold arena scan loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    journal_scan = Path("verification/hosted_cold_journal.rs")
    for label, source, clause, weakness in [
        ("root file magic", journal_scan, "offset,end,limit,frame::ROOT_MAGIC,hash",
         "offset,end,limit,frame::ARENA_MAGIC,hash"),
        ("root offset", journal_scan, "r.replay(history,scheme,offset,", "r.replay(history,scheme,0,"),
        ("journal cursor", journal_scan, "at=next;", "at=end;"),
        ("root projection", journal_scan, "    Ok(history)\n}", "    Ok(BTreeMap::new())\n}"),
        ("recovered root set", reopen, "crate::journal_closure::validate(&history,&table)",
         "crate::journal_closure::validate(&BTreeMap::<P,(RootState,u64)>::new(),&table)"),
    ]:
        yield (
            f"cold root history loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    for label, source, clause, weakness in [
        ("appended principal", journal_scan, "let row=Row {name:name@,key,prior:expected,root:next",
         "let row=Row {name:Seq::empty(),key,prior:expected,root:next"),
        ("physical append address", journal_scan, "let loc=ArenaLocation {offset:prior_image.len() as u64",
         "let loc=ArenaLocation {offset:0"),
        ("reopened history", journal_scan, "let out=recover(reader,end,scheme,limit,hash,decode,recode,Ghost(full));",
         "let out:Result<BTreeMap<P,(RootState,u64)>,(u64,Failure<R::Error>)>=Ok(BTreeMap::new());"),
        ("reserved header precedence", repair, "if !frame::magic_matches(&h,magic)",
         "if h[10]!=0 || !frame::magic_matches(&h,magic)"),
    ]:
        yield (
            f"certified journal append loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    snapshot = Path("verification/hosted_cold_snapshot.rs")
    dispatch = Path("crates/astrid-storage/src/engine/durable/journal_payload.rs")
    for label, source, clause, weakness in [
        ("snapshot write limit", dispatch, "if size>limit {return Err(WriteError::Size(size));}",
         "if false {return Err(WriteError::Size(size));}"),
        ("written frame payload", frames, "if let Err(e)=file.write_bytes(payload)",
         "if let Err(e)=file.write_bytes(&[])"),
        ("reopened snapshot", snapshot, "RoundTrip::Loaded(table)\n", "RoundTrip::Loaded(BTreeMap::new())\n"),
        ("payload kind", dispatch, "Ok(r)=>Ok(Record::Transition(r))",
         "Ok(_)=>Ok(Record::Snapshot(Vec::new()))"),
        ("snapshot count", dispatch, "snapshot::read_complete(bytes,cursor,n,scheme)",
         "snapshot::read_complete(bytes,cursor,0,scheme)"),
        ("restore position", snapshot, "snapshot::restore(&mut table,0,&f.body",
         "snapshot::restore(&mut table,f.end,&f.body"),
        ("restored owners", snapshot, "Ok((table,f.end))", "Ok((BTreeMap::new(),f.end))"),
        ("suffix map", snapshot, "scan_suffix(reader,start,end,base,scheme",
         "scan_suffix(reader,start,end,BTreeMap::new(),scheme"),
        ("suffix cursor", snapshot, "scan_suffix(reader,start,end,base,scheme",
         "scan_suffix(reader,0,end,base,scheme"),
    ]:
        yield (
            f"compacted journal loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    walker = Path("crates/astrid-storage/src/engine/durable/frame_scan.rs")
    visitor = walker.with_name("journal_visitor.rs")
    application = walker.with_name("journal_apply.rs")
    integrated = Path("verification/hosted_journal_scan.rs")
    for label, source, clause, weakness in [
        ("callback offset", walker, "visitor.visit(reader,offset,&f.body)", "visitor.visit(reader,start,&f.body)"),
        ("callback payload", walker, "visitor.visit(reader,offset,&f.body)", "visitor.visit(reader,offset,&[])"),
        ("gapless traversal", walker, "offset=f.end;", "offset=end;"),
        ("refused visitor", walker, "return Err(Stop::Visitor(offset,f.body,e))", "return Ok(())"),
        ("root transition offset", application, "r.replay(table,scheme,at,data", "r.replay(table,scheme,0,data"),
        ("snapshot position", application, "snapshot::restore(table,at,data", "snapshot::restore(table,0,data"),
        ("returned history", visitor, "{self.table}", "{BTreeMap::new()}"),
        ("verified root frame domain", walker, "let window=Window{start:0,end,magic:super::arena_frame::ROOT_MAGIC", "let window=Window{start:0,end,magic:super::arena_frame::ARENA_MAGIC"),
    ]:
        yield (
            f"physical journal scan loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    for label, source, clause, weakness in [
        ("protected boundary", integrated, "repair(media,at,end,protected,e.damage(),ROOT_MAGIC,limit)", "repair(media,at,end,0,e.damage(),ROOT_MAGIC,limit)"),
        ("actual failed cursor", integrated, "repair(media,at,end,protected,e.damage(),ROOT_MAGIC,limit)", "repair(media,protected,end,protected,e.damage(),ROOT_MAGIC,limit)"),
        ("classified tail", integrated, "protected,e.damage(),ROOT_MAGIC,limit)", "protected,crate::frame_repair::Damage::Incomplete,ROOT_MAGIC,limit)"),
        ("repaired history", integrated, "Live::Repaired(at,e,table)", "Live::Repaired(at,e,BTreeMap::new())"),
        ("refused suffix", integrated, "Ok(Outcome::Reject)=>Live::Frame(at,FrameError::Tail(e))", "Ok(Outcome::Reject)=>Live::Repaired(at,e,table)"),
        ("container persistence", walker.with_name("frontier.rs"), "handle.sync_container()?;", "/* skip container sync */"),
        ("container failure", integrated, "Err(e)=>VolumeRecovery::Container(at,e)", "Err(_)=>VolumeRecovery::Unmodified(table)"),
        ("returned volume history", integrated, "Ok(region)=>VolumeRecovery::Persisted(at,table,region)", "Ok(region)=>VolumeRecovery::Persisted(at,BTreeMap::new(),region)"),
    ]:
        yield (
            f"repaired journal loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    backing = walker.with_name("frontier.rs")
    volume = Path("verification/hosted_arena_scan.rs")
    for label, source, clause, weakness in [
        ("native sync", backing, "Self::Native(n)=>{fsync(n)?;Ok(None)}", "Self::Native(_)=>{Ok(None)}"),
        ("returned container", backing, "Ok(Some(handle))", "Ok(None)"),
        ("container failure", backing, "handle.sync_container()?;", "let _=handle.sync_container();"),
        ("arena fence", volume, "Ok(region)=>VolumeIndex::Persisted(at,index,region)", "Ok(_)=>VolumeIndex::Clean(index)"),
        ("arena fence error", volume, "Err(e)=>VolumeIndex::Container(at,e)", "Err(_)=>VolumeIndex::Clean(index)"),
        ("empty arena fence", volume, "if at==end {return VolumeIndex::Clean(index);}", "if at<=end {return VolumeIndex::Clean(index);}"),
        ("returned arena receipt", volume, "state,arena_fence:af,root_fence:rf", "state,arena_fence:None,root_fence:rf"),
        ("returned journal receipt", volume, "state,arena_fence:af,root_fence:rf", "state,arena_fence:af,root_fence:None"),
        ("journal end", volume, "load_history(history,re,&arena,", "load_history(history,end,&arena,"),
        ("physical region separation", volume, "old(scan).target().1!=old(reader).target().1,", "true,"),
    ]:
        yield (
            f"volume repair loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    arena_fold = Path("crates/astrid-storage/src/engine/durable/format/arena_history.rs")
    arena_scan = Path("verification/hosted_arena_scan.rs")
    for label, source, clause, weakness in [
        ("frame domain", walker, "let window=Window{start:0,end,magic:super::arena_frame::ARENA_MAGIC",
         "let window=Window{start:0,end,magic:super::arena_frame::ROOT_MAGIC"),
        ("frame payload", arena_fold, "self.index.accept(at,data,", "self.index.accept(at,&[],"),
        ("physical offset", arena_fold, "self.index.accept(at,data,", "self.index.accept(0,data,"),
        ("first placement", arena_fold, "    {self.index.finish()}", "    {(BTreeMap::new(),None)}"),
        ("protected extent", arena_scan, "repair(media,at,end,protected,e.damage()", "repair(media,at,end,0,e.damage()"),
        ("recovered extent", arena_scan, "Recovery::Loaded(at,(map,tail))\n", "Recovery::Loaded(end,(map,tail))\n"),
        ("measured arena end", arena_scan, "recover(scan,backing,arena_end,arena_protected", "recover(scan,backing,0,arena_protected"),
        ("positional identity", arena_scan, "a.target()==m.target() && a.image()==m.durable()", "a.image()==m.durable()"),
        ("positional image", arena_scan, "a.target()==m.target() && a.image()==m.durable()", "a.target()==m.target()"),
        ("refusal cause", arena_scan, "return Recovery::Record(at,b,e);", "return Recovery::Record(at,b,IndexError::Collision(ObjectId::new([0;32])));"),
        ("restored index", arena_scan, "Some(Reopened{loaded,arena_end:at,index:Ghost(index@)", "Some(Reopened{loaded,arena_end:at,index:Ghost(Map::empty())"),
    ]:
        yield (
            f"arbitrary arena recovery loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    arena_index = Path("crates/astrid-storage/src/engine/durable/format/recovered_record.rs")
    for label, clause, weakness in [
        ("physical offset", "index(&mut self.entries,at,data", "index(&mut self.entries,0,data"),
        ("last accepted frame", "self.tail=Some(location);", "if self.tail.is_none() {self.tail=Some(location);}"),
        ("complete index", "{ (self.entries,self.tail) }", "{ (BTreeMap::new(),self.tail) }"),
    ]:
        yield (
            f"native arena index loses {label}", arena_index,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), arena_index,
        )

    loaded = Path("verification/hosted_recovered_roots.rs")
    for label, source, clause, weakness in [
        ("persisted end", loaded, "history:Ghost(history@),end:at", "history:Ghost(history@),end:0"),
        ("root projection", loaded, "let v=Loaded{roots,records", "let v=Loaded{roots:BTreeMap::new(),records"),
        ("restored object domain", loaded, "roots,records,known,history:Ghost", "roots,records,known:BTreeSet::new(),history:Ghost"),
        ("separate physical targets", loaded, "arena.target()!=old(reader).target(),", "true,"),
        ("journal protection", loaded, "recover_live(reader,media,end,protected,limit", "recover_live(reader,media,end,0,limit"),
        ("arena scan extent", reopen, "rebuild(scan,0,arena_end,scheme", "rebuild(scan,0,0,scheme"),
        ("arena read identity", reopen, "receipt.target@==arena.target(),", "true,"),
    ]:
        yield (
            f"retained root recovery loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )

    transition = walker.with_name("journal_transition.rs")
    for label, source, clause, weakness, consumer in [
        ("diagnostic position", walker, "return Err(Stop::Visitor(offset,f.body,e))",
         "return Err(Stop::Visitor(start,f.body,e))", walker),
        ("diagnostic bytes", walker, "return Err(Stop::Visitor(offset,f.body,e))",
         "return Err(Stop::Visitor(offset,Vec::new(),e))", walker),
        ("conflicting predecessor", transition, "actual==seen && actual!=expected",
         "actual==seen && actual==expected", transition),
        ("snapshot refusal cause", application, "Err(Error::Snapshot(e))\n",
         "Err(Error::Snapshot(snapshot::SnapshotError::Position))\n", application),
        ("conflict diagnostics", application, "Err(Error::Transition(r.expected,e))\n",
         "Err(Error::Transition(None,e))\n", application),
        ("unknown record reason", dispatch, "data.len()>=9 && first==snapshot::SENTINEL",
         "data.len()<9 && first==snapshot::SENTINEL", dispatch),
    ]:
        yield (
            f"root refusal loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), consumer,
        )

    probe = walker.with_name("frame_probe.rs")
    for label, source, clause, weakness in [
        ("incomplete-payload barrier", repair, "ensures result==self.classification(),\n    {\n        match self {\n            Self::HeaderShort =>",
         "ensures result==self.classification(),\n    {\n        match self {\n            Self::HeaderShort | Self::PayloadShort =>"),
        ("search start", repair, "let start=offset.saturating_add(1);", "let start=offset.saturating_add(2);"),
        ("candidate address", probe, "candidate(media,at,end,magic,limit)?", "candidate(media,offset,end,magic,limit)?"),
        ("window overlap", probe, "offset=offset.saturating_add(i as u64);", "offset=offset.saturating_add(count as u64);"),
        ("read refusal", probe, "if let Err(e)=media.read_window(offset,window) {return Err(Error::Io(e));}",
         "if let Err(_e)=media.read_window(offset,window) {return Ok(false);}"),
        ("oversize protection", probe, "if n>limit {return Ok(true);}", "if n>limit {return Ok(false);}"),
        ("hash domain", probe, "M::prepare_hash(magic,length)", "M::prepare_hash([0u8;8],length)"),
        ("hash chunk", probe, "hash.absorb(part);", "hash.absorb(&[]);"),
        ("payload cursor", probe, "left=left.saturating_sub(count as u64);", "left=0;"),
        ("candidate checksum", probe, "let matches=sum.as_slice()==decoded.checksum.as_slice();", "let matches=true;"),
        ("later-frame truncation guard", repair, "return Ok(Outcome::Reject)\n", "return Ok(Outcome::Repaired)\n"),
    ]:
        yield (
            f"physical repair probe loses {label}", source,
            lambda s, a=clause, b=weakness: replace_once(s, a, b), source,
        )
