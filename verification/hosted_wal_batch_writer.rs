//! Construct a scanner layout while emitting an arbitrary number of measured records.
use super::*;

verus! {

struct Prefix<'a> {
    stream:Vec<u8>,data:Vec<u8>,counts:Counts,ends:Vec<usize>,
    rows:Ghost<Seq<Record<'a>>>,states:Ghost<Seq<Counts>>,
}

#[verifier::opaque]
spec fn prefix_rows(stream:Seq<u8>,rows:Seq<Record>,states:Seq<Counts>,sum:spec_fn(Seq<u8>)->[u8;32]) -> bool {
    let first=rows[0];
    let c=states[0];
    &&& rows.len()>0 && rows.len()==states.len()
    &&& at_record(stream,0,first,u64::MAX,sum) && first.kind is Begin && first.ordinal==0
    &&& c.sequence==first.sequence && c.logical==1 && c.objects==0 && c.roots==0
    &&& c.bytes as int==logical::HEADER_LEN as int+first.body.len()
    &&& forall|i:int| 0<i<rows.len() ==> at_record(stream,rows[i-1].next as int,#[trigger] rows[i],u64::MAX,sum)
        && step(rows[i],states[i-1],states[i])
}

proof fn extend_record(old:Seq<u8>,tail:Seq<u8>,at:int,row:Record,sum:spec_fn(Seq<u8>)->[u8;32])
    requires at_record(old,at,row,u64::MAX,sum),
    ensures at_record(old+tail,at,row,u64::MAX,sum),
{
    reveal(at_record);
    assert((old+tail).subrange(at,row.next as int) =~= old.subrange(at,row.next as int));
}

proof fn extend_prefix(old:Seq<u8>,tail:Seq<u8>,rows:Seq<Record>,states:Seq<Counts>,sum:spec_fn(Seq<u8>)->[u8;32])
    requires prefix_rows(old,rows,states,sum),
    ensures prefix_rows(old+tail,rows,states,sum),
{
    reveal(prefix_rows);
    extend_record(old,tail,0,rows[0],sum);
    assert forall|i:int| 0<i<rows.len() implies at_record(old+tail,rows[i-1].next as int,#[trigger] rows[i],u64::MAX,sum)
        && step(rows[i],states[i-1],states[i]) by {
        extend_record(old,tail,rows[i-1].next as int,rows[i],sum);
    }
}

#[verifier::spinoff_prover]
#[verifier::rlimit(35)]
proof fn push_prefix<'a>(before:Seq<u8>,frame:Seq<u8>,rows:Seq<Record<'a>>,states:Seq<Counts>,
    row:Record<'a>,count:Counts,sum:spec_fn(Seq<u8>)->[u8;32])
    requires prefix_rows(before,rows,states,sum),rows.last().next==before.len(),
        at_record(before+frame,before.len() as int,row,u64::MAX,sum),step(row,states.last(),count),
    ensures prefix_rows(before+frame,rows.push(row),states.push(count),sum),
{
    extend_prefix(before,frame,rows,states,sum);
    reveal(prefix_rows);
    assert(rows.len()>0);
    let next=rows.push(row);
    let ns=states.push(count);
    assert forall|i:int| 0<i<next.len() implies at_record(before+frame,next[i-1].next as int,#[trigger] next[i],u64::MAX,sum)
        && step(next[i],ns[i-1],ns[i]) by {
        if i<rows.len() {assert(next[i]==rows[i]);}
        else {assert(i==rows.len());}
    }
}

impl<'a> Prefix<'a> {
    spec fn valid(&self,sequence:u64,sum:spec_fn(Seq<u8>)->[u8;32]) -> bool {
        &&& prefix_rows(self.stream@,self.rows@,self.states@,sum)
        &&& self.rows@.last().next==self.stream.len() && self.counts==self.states@.last()
        &&& sequence!=0 && self.counts.sequence==sequence && self.counts.logical==self.rows@.len()
        &&& self.counts.bytes<=self.stream.len() && self.counts.logical<=self.stream.len()
        &&& self.counts.objects<=self.counts.logical && self.counts.roots<=self.counts.logical
        &&& self.ends.len()==self.rows@.len()
        &&& self.ends@.last()==self.stream.len()
        &&& forall|i:int| 0<=i<self.ends.len() ==> (#[trigger] self.ends@[i])==self.rows@[i].next &&
            0<self.ends@[i]<=self.stream.len() && (i>0 ==> self.ends@[i-1]<self.ends@[i])
        &&& self.data@==transcript(self.rows@)
    }

    #[verifier::spinoff_prover]
    #[verifier::rlimit(25)]
    fn begin<H>(sequence:u64,body:&'a [u8],hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
        -> (out:Self) where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        requires sequence!=0,body.len()+72<=usize::MAX,
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        ensures out.valid(sequence,checksum@),out.rows@.len()==1,out.rows@[0].body==body, out.data@==wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,body.len() as u64)+body@,
            out.stream.len()==body.len()+72,out.counts.roots==0,out.counts.objects==0,
    {
        let (stream,counts,data)=write_data(Measured::begin(sequence,body).ok().unwrap(),hash,checksum).unwrap();
        let row=Record{next:stream.len(),kind:WalRecordKind::Begin,flags:0,sequence,ordinal:0,body};
        let ghost rows=seq![row];
        proof {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            reveal(at_record);
            assert(stream@.subrange(0,row.next as int) =~= stream@);
            assert(at_record(stream@,0,row,u64::MAX,checksum@));
            reveal_with_fuel(transcript,2);
            assert(rows.drop_last() =~= Seq::<Record>::empty());
            assert(data@ =~= transcript(rows));
        }
        let ghost states=seq![counts];
        let ends=vec![stream.len()];
        let made=Prefix{stream,data,counts,ends,rows:Ghost(rows),states:Ghost(states)};
        proof {
            assert(prefix_rows(made.stream@,rows,states,checksum@)) by {reveal(prefix_rows);}
            assert(row.next==72+body.len()) by {reveal(at_record);}
            assert(made.ends.len()==1);
            assert(made.ends@[0]==made.stream.len()==row.next);
            assert(made.ends@.last()==made.stream.len());
            assert forall|i:int| 0<=i<made.ends.len() implies (#[trigger] made.ends@[i])==made.rows@[i].next &&
                0<made.ends@[i]<=made.stream.len() && (i>0 ==> made.ends@[i-1]<made.ends@[i]) by {assert(i==0);}
            assert(made.valid(sequence,checksum@));
        }
        made
    }

    #[verifier::spinoff_prover]
    #[verifier::rlimit(30)]
    fn append<H>(mut self,entry:DataKind,body:&'a [u8],hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
        -> (out:Self) where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        requires self.valid(self.counts.sequence,checksum@),self.stream.len() as int+72+body.len()<=usize::MAX,
            entry is Object ==> self.counts.roots==0,
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        ensures out.valid(self.counts.sequence,checksum@),out.rows@.drop_last()==self.rows@,
            out.rows@.last().body==body,out.rows@.last().ordinal==self.counts.logical,out.rows@.last().sequence==self.counts.sequence,
            out.counts.logical as int==self.counts.logical+1,out.data@==self.data@+chunk(out.rows@.last()),
            out.rows@.last().next==out.stream.len()==self.stream.len()+72+body.len(),
            out.stream@.take(self.stream.len() as int)==self.stream@,
            match entry {
                DataKind::Object(f)=>out.rows@.last().kind is Object && out.rows@.last().flags==f.flag() &&
                    out.counts.objects as int==self.counts.objects+1 && out.counts.roots==0,
                DataKind::Root=>out.rows@.last().kind is Root && out.rows@.last().flags==0 &&
                    out.counts.roots as int==self.counts.roots+1 && out.counts.objects==self.counts.objects,
            },
    {
        let ghost original=self;
        let (kind,flags)=match entry {DataKind::Object(f)=>(WalRecordKind::Object,f.wire_flag()),DataKind::Root=>(WalRecordKind::Root,0)};
        let (frame,counts,part)=write_data(Measured::append(self.counts,entry,body).ok().unwrap(),hash,checksum).unwrap();
        self.stream.extend_from_slice(&frame);
        self.data.extend_from_slice(&part);
        let row=Record{next:self.stream.len(),kind,flags,sequence:counts.sequence,ordinal:self.counts.logical,body};
        let ghost rows=self.rows@.push(row);
        let ghost states=self.states@.push(counts);
        proof {
            assert(self.stream@ =~= original.stream@+frame@);
            assert(self.stream@.take(original.stream.len() as int) =~= original.stream@);
            assert(self.stream@.subrange(original.stream.len() as int,row.next as int) =~= frame@);
            assert(at_record(self.stream@,original.stream.len() as int,row,u64::MAX,checksum@)) by {
                reveal(at_record);
                vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            }
            assert(row.next as int==original.stream.len() as int+72+body.len()) by {reveal(at_record);}
            assert(step(row,self.counts,counts));
            push_prefix(original.stream@,frame@,self.rows@,self.states@,row,counts,checksum@);
            assert(rows.drop_last() =~= original.rows@);
            assert(self.data@ =~= original.data@+chunk(row));
            assert(self.data@==transcript(rows));
        }
        self.ends.push(row.next);
        assert forall|i:int| 0<=i<self.ends.len() implies (#[trigger] self.ends@[i])==rows[i].next &&
            0<self.ends@[i]<=self.stream.len() && (i>0 ==> self.ends@[i-1]<self.ends@[i]) by {
            if i<original.ends.len() {assert(self.ends@[i]==original.ends@[i]);}
        }
        Prefix{stream:self.stream,data:self.data,counts,ends:self.ends,rows:Ghost(rows),states:Ghost(states)}
    }
}

struct Captured { start:u64,flags:u8,body:Vec<u8> }

spec fn captures(c:Captured,r:Record,base:u64) -> bool {
    &&& c.start as int==base as int+r.next-72-r.body.len()
    &&& c.flags==r.flags && c.body@==r.body@
}

fn capture(rows:&[Record],base:u64) -> (out:Vec<Captured>)
    requires forall|i:int| 0<=i<rows.len() ==> 72+rows@[i].body.len()<=#[trigger] rows@[i].next &&
        base as int+rows@[i].next<=u64::MAX,
    ensures out.len()==rows.len(),forall|i:int| 0<=i<rows.len() ==> #[trigger] captures(out@[i],rows@[i],base),
{
    let mut out=Vec::with_capacity(rows.len());
    let mut i=0usize;
    while i<rows.len()
        invariant i<=rows.len(),i==out.len(),
            forall|j:int| 0<=j<i ==> #[trigger] captures(out@[j],rows@[j],base),
            forall|j:int| 0<=j<rows.len() ==> 72+rows@[j].body.len()<=#[trigger] rows@[j].next &&
                base as int+rows@[j].next<=u64::MAX,
        decreases rows.len()-i,
    {
        let row=rows[i];
        let mut body=Vec::new();body.extend_from_slice(row.body);
        assert(body@ =~= row.body@);
        assert(72+row.body.len()<=row.next);
        let captured=Captured{start:base+(row.next-72-row.body.len()) as u64,flags:row.flags,body};
        assert(captures(captured,row,base));
        let ghost previous=out@;
        out.push(captured);
        assert forall|j:int| 0<=j<=i implies #[trigger] captures(out@[j],rows@[j],base) by {
            if j<i {assert(captures(previous[j],rows@[j],base));}
        }
        i+=1;
    }
    out
}

proof fn selection_members(rows:Seq<Record>,kind:WalRecordKind,r:Record)
    requires selected(rows,kind).contains(r), ensures rows.contains(r),
    decreases rows.len(),
{
    if rows.len()>0 {
        if r!=rows.last() || rows.last().kind!=kind {selection_members(rows.drop_last(),kind,r);}
        if rows.drop_last().contains(r) {
            let i=choose|i:int| 0<=i<rows.drop_last().len() && rows.drop_last()[i]==r;
            assert(rows[i]==r);
        } else {assert(rows[rows.len()-1]==r);}
    }
}

struct Released<M> { media:M, marker:CheckedMarker, objects:Vec<Captured>, roots:Vec<Captured> }

spec fn released_rows(c:Seq<Captured>,rows:Seq<Record>,base:u64,image:Seq<u8>) -> bool {
    &&& c.len()==rows.len()
    &&& forall|i:int| 0<=i<c.len() ==> #[trigger] captures(c[i],rows[i],base) &&
        base<=c[i].start && c[i].start as int+72+c[i].body.len()<=image.len() &&
        image.subrange(c[i].start as int+72,c[i].start as int+72+c[i].body.len())==c[i].body@
}

#[verifier::spinoff_prover]
#[verifier::rlimit(25)]
proof fn stored_member(rows:Seq<Record>,states:Seq<Counts>,kind:WalRecordKind,r:Record,stream:Seq<u8>,sum:spec_fn(Seq<u8>)->[u8;32])
    requires prefix_rows(stream,rows,states,sum),selected(rows,kind).contains(r),
    ensures 72+r.body.len()<=r.next<=stream.len(),
        stream.subrange(r.next as int-r.body.len(),r.next as int)==r.body@,
{
    selection_members(rows,kind,r);
    let i=choose|i:int| 0<=i<rows.len() && rows[i]==r;
    let at=if i==0 {0int} else {rows[i-1].next as int};
    assert(at_record(stream,at,r,u64::MAX,sum)) by {reveal(prefix_rows);if i>0 {assert(rows[i]==r);}}
    reveal(at_record);
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    let interval=stream.subrange(at,r.next as int);
    assert(interval.skip(72) =~= r.body@);
    assert(stream.subrange(r.next as int-r.body.len(),r.next as int) =~= interval.skip(72));
}

proof fn located(rows:Seq<Record>,states:Seq<Counts>,kind:WalRecordKind,c:Seq<Captured>,base:u64,prior:Seq<u8>,
    bytes:Seq<u8>,sum:spec_fn(Seq<u8>)->[u8;32])
    requires prefix_rows(bytes,rows,states,sum),prior.len()==base,c.len()==selected(rows,kind).len(),
        forall|i:int| 0<=i<c.len() ==> #[trigger] captures(c[i],selected(rows,kind)[i],base),
    ensures released_rows(c,selected(rows,kind),base,prior+bytes),
{
    let picked=selected(rows,kind);
    assert forall|i:int| 0<=i<c.len() implies #[trigger] captures(c[i],picked[i],base) &&
        base<=c[i].start && c[i].start as int+72+c[i].body.len()<=(prior+bytes).len() &&
        (prior+bytes).subrange(c[i].start as int+72,c[i].start as int+72+c[i].body.len())==c[i].body@ by {
        let r=picked[i];
        assert(picked.contains(r));
        assert(captures(c[i],r,base));
        stored_member(rows,states,kind,r,bytes,sum);
        assert((prior+bytes).subrange(base as int+r.next-r.body.len(),base as int+r.next) =~= bytes.subrange(r.next as int-r.body.len(),r.next as int));
    }
}

/// Submit one slice per physical frame, including the trailing Commit frame.
fn submit_frames<S:crate::group_frontier::BufferedWal>(sink:S,stream:&[u8],ends:&[usize],last:usize) -> (wal:S)
    requires sink.at_end(),ends.len()>0,ends@.last()==last,last<stream.len(),
        forall|j:int| 0<=j<ends.len() ==> 0<(#[trigger] ends@[j])<=last && (j>0 ==> ends@[j-1]<ends@[j]),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
    ensures wal.wal_target()==sink.wal_target(),wal.buffered_image()==sink.buffered_image()+stream@,
{
    let ghost prior=sink.buffered_image();
    let ghost wal_id=sink.wal_target();
    let mut wal=sink;
    let mut start=0usize;
    let mut i=0usize;
    while i<ends.len()
        invariant i<=ends.len(),start==if i==0 {0usize} else {ends@[i-1]},
            ends.len()>0,ends@.last()==last,start<=last,
            forall|j:int| 0<=j<ends.len() ==> 0<(#[trigger] ends@[j])<=last &&
                (j>0 ==> ends@[j-1]<ends@[j]),
            last<stream.len(),wal.at_end(),wal.wal_target()==wal_id,
            wal.buffered_image()==prior+stream@.take(start as int),
            forall|s:S,e:S::Error| s.wal_target()==wal_id ==> !#[trigger] s.append_error(e),
        decreases ends.len()-i,
    {
        let end=ends[i];
        wal.append_record(&stream[start..end]).ok().unwrap();
        assert(wal.buffered_image() =~= prior+stream@.take(end as int));
        start=end;
        i+=1;
    }
    wal.append_record(&stream[start..]).ok().unwrap();
    assert(wal.buffered_image() =~= prior+stream@);
    wal
}

#[verifier::spinoff_prover]
#[verifier::rlimit(30)]
fn scan_released<'a,M:crate::positional_read::Media,H,F>(media:M,bytes:&'a [u8],base:u64,chunk_size:usize,
    hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    Ghost(layout):Ghost<Layout<'a>>,Ghost(prior):Ghost<Seq<u8>>) -> (out:Released<M>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires complete(layout,bytes@,0,u64::MAX,checksum@,digest@),prefix_rows(bytes@,layout.rows,layout.states,checksum@),
        media.image()==prior+bytes@,prior.len()==base,base as int+bytes.len()<=u64::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
    ensures out.media==media,out.marker.marker()==(commit_wire::Marker{counts:layout.states.last(),digest:(digest@)(transcript(layout.rows))}),
        released_rows(out.objects@,selected(layout.rows,WalRecordKind::Object),base,media.image()),
        released_rows(out.roots@,selected(layout.rows,WalRecordKind::Root),base,media.image()),
{
    let got=scan_transaction(bytes,0,u64::MAX,chunk_size,hash,checksum,finish,digest,Ghost(Some(layout))).unwrap();
    let objects=got.batch.objects();
    let roots=got.batch.roots();
    proof {
        assert forall|i:int| 0<=i<objects.len() implies 72+objects@[i].body.len()<=#[trigger] objects@[i].next &&
            base as int+objects@[i].next<=u64::MAX by {stored_member(layout.rows,layout.states,WalRecordKind::Object,objects@[i],bytes@,checksum@);}
        assert forall|i:int| 0<=i<roots.len() implies 72+roots@[i].body.len()<=#[trigger] roots@[i].next &&
            base as int+roots@[i].next<=u64::MAX by {stored_member(layout.rows,layout.states,WalRecordKind::Root,roots@[i],bytes@,checksum@);}
    }
    let os=capture(objects,base);
    let rs=capture(roots,base);
    proof {
        assert(media.image().take(base as int) =~= prior);
        located(layout.rows,layout.states,WalRecordKind::Object,os@,base,prior,bytes@,checksum@);
        located(layout.rows,layout.states,WalRecordKind::Root,rs@,base,prior,bytes@,checksum@);
    }
    Released{media,marker:got.marker,objects:os,roots:rs}
}

fn commit_frame<H>(stream:&mut Vec<u8>,marker:&commit_wire::Marker,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (body:[u8;72]) where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(stream).len()+144<=usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
    ensures final(stream)@==old(stream)@+frame_bytes(marker.payload(),1,checksum@),
        final(stream).len()==old(stream).len()+144,body@==marker.wire(),
{
    let frame=marker.frame(vec![0u8;52],hash).unwrap();
    let body=marker.encode();
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let (p,q)=choose|p:&[u8],q:[u8;32]| p@==marker.payload() && #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            frame@==(physical::Envelope{version:1,size:p.len() as u64,checksum:q}).wire()+p@;
        assert(hash.ensures((physical::MAGIC,p.len() as u64,p),q));
        assert(frame@==frame_bytes(marker.payload(),1,checksum@));
        assert(frame.len()==144);
    }
    stream.extend_from_slice(&frame);
    body
}

proof fn close_layout(w:Layout,before:Seq<u8>,stream:Seq<u8>,m:commit_wire::Marker,sum:spec_fn(Seq<u8>)->[u8;32],digest:spec_fn(Seq<u8>)->[u8;32])
    requires prefix_rows(before,w.rows,w.states,sum),w.rows.last().next==before.len(),w.states.last()==m.counts,
        m.counts.sequence!=0,m.counts.roots>0,m.digest==digest(transcript(w.rows)),
        w.commit.kind is Commit,w.commit.flags==0,w.commit.sequence==m.counts.sequence,w.commit.ordinal==m.counts.logical,
        w.commit.next==stream.len(),w.commit.body@==m.wire(),stream.len()==before.len()+144,
        stream==before+frame_bytes(m.payload(),1,sum),
    ensures prefix_rows(stream,w.rows,w.states,sum),complete(w,stream,0,u64::MAX,sum,digest),
{
    let frame=frame_bytes(m.payload(),1,sum);
    extend_prefix(before,frame,w.rows,w.states,sum);
    assert(stream.subrange(before.len() as int,w.commit.next as int) =~= frame);
    assert(at_record(stream,before.len() as int,w.commit,u64::MAX,sum)) by {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        reveal(at_record);
    }
    reveal(prefix_rows);
    reveal(complete);
}

/// Publish the submitted physical frames and reread them from the same WAL target.
fn acknowledge<S:crate::group_frontier::BufferedWal,M:crate::positional_read::Media,Open:FnOnce(&S)->M>(
    sink:S,stream:&[u8],ends:&[usize],last:usize,base:u64,reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
    -> (out:(M,Vec<u8>))
    requires sink.at_end(),sink.buffered_image().len()==base,base as int+stream.len()<=u64::MAX,
        ends.len()>0,ends@.last()==last,last<stream.len(),
        forall|j:int| 0<=j<ends.len() ==> 0<(#[trigger] ends@[j])<=last && (j>0 ==> ends@[j-1]<ends@[j]),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
        forall|s:&S| #[trigger] reopen.requires((s,)),
        forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
            forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
    ensures out.1@==stream@ && out.0.image()==sink.buffered_image()+stream@ && (target@)(out.0)==sink.wal_target(),
{
    let ghost prior=sink.buffered_image();
    let wal=submit_frames(sink,stream,ends,last);
    sync_and_read(wal,stream,base,reopen,target,Ghost(prior)).unwrap()
}

impl<'a> Prefix<'a> {
    /// Append Commit, acknowledge the buffered WAL, then scan its stable bytes.
    #[verifier::spinoff_prover]
    #[verifier::rlimit(35)]
    fn seal<M:crate::positional_read::Media,S:crate::group_frontier::BufferedWal,H,F,Open>(mut self,sink:S,base:u64,chunk_size:usize,
        hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
        reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
        -> (out:Released<M>)
        where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,Open:FnOnce(&S)->M,
        requires self.valid(self.counts.sequence,checksum@),self.counts.roots>0,sink.at_end(),sink.buffered_image().len()==base,
            base as int+self.stream.len()+144<=u64::MAX,self.stream.len()+144<=usize::MAX,
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
            forall|p:&[u8]| #[trigger] finish.requires((p,)),
            forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
        ensures out.media.image().take(base as int)==sink.buffered_image(), (target@)(out.media)==sink.wal_target(),
            out.media.image().len()==base+self.stream.len()+144,
            out.media.image().subrange(base as int,base as int+self.stream.len())==self.stream@,
            out.marker.marker()==(commit_wire::Marker{counts:self.counts,digest:(digest@)(transcript(self.rows@))}),
            released_rows(out.objects@,selected(self.rows@,WalRecordKind::Object),base,out.media.image()),
            released_rows(out.roots@,selected(self.rows@,WalRecordKind::Root),base,out.media.image()),
    {
        let ghost old=self;
        let text=self.data.as_slice();
        let sum=finish(text);
        let marker=commit_wire::Marker{counts:self.counts,digest:sum};
        let start_of_commit=self.stream.len();
        let body=commit_frame(&mut self.stream,&marker,hash,checksum);
        let commit=Record{next:self.stream.len(),kind:WalRecordKind::Commit,flags:0,sequence:self.counts.sequence,
            ordinal:self.counts.logical,body:&body};
        let ghost layout=Layout{rows:self.rows@,states:self.states@,commit};
        proof {
            assert(finish.ensures((text,),sum));
            close_layout(layout,old.stream@,self.stream@,marker,checksum@,digest@);
            assert(self.stream@.take(old.stream.len() as int) =~= old.stream@);
        }
        let ghost prior=sink.buffered_image();
        assert(self.ends.len()>0);
        assert forall|j:int| 0<=j<self.ends.len() implies 0<(#[trigger] self.ends@[j])<=start_of_commit &&
            (j>0 ==> self.ends@[j-1]<self.ends@[j]) by {assert(self.ends@[j]==old.ends@[j]);}
        let (media,bytes)=acknowledge(sink,&self.stream,&self.ends,start_of_commit,base,reopen,target);
        proof {
            assert(media.image().take(base as int) =~= prior);
            assert(media.image().subrange(base as int,base as int+old.stream.len()) =~= old.stream@);
        }
        scan_released(media,&bytes,base,chunk_size,hash,checksum,finish,digest,Ghost(layout),Ghost(prior))
    }
}

struct Stored<'a> { encoding:ObjectEncoding, body:&'a [u8] }

spec fn extent(objects:Seq<Stored>,count:nat) -> nat
    decreases count,
{
    if count==0 {0} else {extent(objects,(count-1) as nat)+72nat+objects[count-1].body.len() as nat}
}

spec fn object_transcript(objects:Seq<Stored>,count:nat,sequence:u64) -> Seq<u8>
    decreases count,
{
    if count==0 {Seq::empty()} else {
        let o=objects[count-1];
        object_transcript(objects,(count-1) as nat,sequence)+
            wal_measurement::digest_header(WalRecordKind::Object,o.encoding.flag(),sequence,count as u64,o.body.len() as u64)+o.body@
    }
}

spec fn group_transcript(sequence:u64,begin:Seq<u8>,objects:Seq<Stored>,root:Seq<u8>) -> Seq<u8> {
    wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin+
        object_transcript(objects,objects.len(),sequence)+
        wal_measurement::digest_header(WalRecordKind::Root,0,sequence,(objects.len()+1) as u64,root.len() as u64)+root
}

proof fn extent_le(objects:Seq<Stored>,i:nat,n:nat)
    requires i<=n<=objects.len(),ensures extent(objects,i)<=extent(objects,n),
    decreases n-i,
{
    if i<n {extent_le(objects,i,(n-1) as nat);}
}

spec fn stored_prefix(rows:Seq<Record>,input:Seq<Stored>,count:nat,first:int) -> bool {
    let picked=selected(rows,WalRecordKind::Object);
    &&& picked.len()==count
    &&& forall|i:int| 0<=i<count ==> (#[trigger] picked[i]).body==input[i].body &&
        picked[i].flags==input[i].encoding.flag() && picked[i].next as int==first+extent(input,(i+1) as nat)
}

/// A representable sequence of stored objects, including an empty sequence,
/// is framed in its supplied order before the single selected root.
#[verifier::spinoff_prover]
#[verifier::rlimit(30)]
fn build<'a,H>(sequence:u64,begin:&'a [u8],objects:&[Stored<'a>],root:&'a [u8],hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>) -> (out:Prefix<'a>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires sequence!=0,144+begin.len()+extent(objects@,objects.len() as nat)+root.len()<=usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
    ensures out.valid(sequence,checksum@),out.counts.objects==objects.len(),out.counts.roots==1,
        out.stream.len()==144+begin.len()+extent(objects@,objects.len() as nat)+root.len(),
        stored_prefix(out.rows@,objects@,objects.len() as nat,72+begin.len()),
        selected(out.rows@,WalRecordKind::Root).len()==1 && selected(out.rows@,WalRecordKind::Root)[0].body==root &&
        selected(out.rows@,WalRecordKind::Root)[0].next==out.stream.len() && selected(out.rows@,WalRecordKind::Root)[0].flags==0,
        out.data@==group_transcript(sequence,begin@,objects@,root@),out.counts.logical as int==objects.len()+2,
{
    let ghost first=wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@;
    let mut prefix=Prefix::begin(sequence,begin,hash,checksum);
    proof {
        reveal_with_fuel(selected,2);
        assert(prefix.rows@.drop_last() =~= Seq::<Record>::empty());
        assert(prefix.rows@[0].kind is Begin) by {reveal(prefix_rows);}
    }
    let mut i=0usize;
    while i<objects.len()
        invariant forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
            144+begin.len()+extent(objects@,objects.len() as nat)+root.len()<=usize::MAX,
            i<=objects.len(),prefix.valid(sequence,checksum@),prefix.counts.objects==i,prefix.counts.roots==0,
            prefix.counts.logical as int==i+1,prefix.data@==first+object_transcript(objects@,i as nat,sequence),
            prefix.stream.len()==72+begin.len()+extent(objects@,i as nat),
            stored_prefix(prefix.rows@,objects@,i as nat,72+begin.len()),
            selected(prefix.rows@,WalRecordKind::Root).len()==0,
        decreases objects.len()-i,
    {
        let body=objects[i].body;
        proof {
            extent_le(objects@,(i+1) as nat,objects.len() as nat);
            assert(extent(objects@,(i+1) as nat)==extent(objects@,i as nat)+72+body.len());
        }
        let ghost before=prefix.rows@;
        prefix=prefix.append(DataKind::Object(objects[i].encoding),body,hash,checksum);
        proof {
            let after=prefix.rows@;
            assert(prefix.data@ =~= first+object_transcript(objects@,(i+1) as nat,sequence));
            let old=selected(before,WalRecordKind::Object);
            let picked=selected(after,WalRecordKind::Object);
            assert(after.len()>0);
            assert(picked==old.push(after.last()));
            assert forall|j:int| 0<=j<=i implies (#[trigger] picked[j]).body==objects@[j].body &&
                picked[j].flags==objects@[j].encoding.flag() &&
                picked[j].next as int==72+begin.len()+extent(objects@,(j+1) as nat) by {
                if j<i {assert(picked[j]==old[j]);} else {assert(j==i);}
            }
        }
        i+=1;
    }
    let ghost before=prefix.rows@;
    prefix=prefix.append(DataKind::Root,root,hash,checksum);
    assert(prefix.data@ =~= group_transcript(sequence,begin@,objects@,root@));
    assert(selected(prefix.rows@,WalRecordKind::Object)==selected(before,WalRecordKind::Object));
    assert(selected(prefix.rows@,WalRecordKind::Root) =~= seq![prefix.rows@.last()]);
    prefix
}

/// Acknowledge the entire variable-size group before releasing any descriptors.
/// Offsets are absolute in the reopened WAL and cover the actual stored bodies.
#[verifier::spinoff_prover]
#[verifier::rlimit(30)]
fn write_group<M:crate::positional_read::Media,S:crate::group_frontier::BufferedWal,H,F,Open>(
    sequence:u64,begin:&[u8],objects:&[Stored],root:&[u8],sink:S,base:u64,chunk_size:usize,
    hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>) -> (r:Released<M>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,Open:FnOnce(&S)->M,
    requires sequence!=0,sink.at_end(),sink.buffered_image().len()==base,
        288+begin.len()+extent(objects@,objects.len() as nat)+root.len()<=usize::MAX,
        base as int+288+begin.len()+extent(objects@,objects.len() as nat)+root.len()<=u64::MAX,
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
            forall|p:&[u8]| #[trigger] finish.requires((p,)),
            forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
    ensures (target@)(r.media)==sink.wal_target(),r.media.image().take(base as int)==sink.buffered_image(),
        r.media.image().len()==base as int+288+begin.len()+extent(objects@,objects.len() as nat)+root.len(),
        r.marker.marker().counts.sequence==sequence,r.marker.marker().counts.objects==objects.len(),r.marker.marker().counts.roots==1,
        r.marker.marker().counts.logical as int==objects.len()+2,r.marker.marker().digest==(digest@)(group_transcript(sequence,begin@,objects@,root@)),
        r.objects.len()==objects.len(),r.roots.len()==1,r.roots@[0].flags==0,r.roots@[0].body@==root@,
        r.roots@[0].start as int==base as int+72+begin.len()+extent(objects@,objects.len() as nat),
        r.media.image().subrange(r.roots@[0].start as int+72,r.roots@[0].start as int+72+root.len())==root@,
        forall|i:int| 0<=i<objects.len() ==> {
            let o=#[trigger] r.objects@[i];
            &&& o.body@==objects@[i].body@ && o.flags==objects@[i].encoding.flag()
            &&& o.start as int==base as int+72+begin.len()+extent(objects@,i as nat)
            &&& r.media.image().subrange(o.start as int+72,o.start as int+72+o.body.len())==o.body@
        },
{
    let prefix=build(sequence,begin,objects,root,hash,checksum);
    let r=prefix.seal(sink,base,chunk_size,hash,checksum,finish,digest,reopen,target);
    proof {
        let os=selected(prefix.rows@,WalRecordKind::Object);
        let rs=selected(prefix.rows@,WalRecordKind::Root);
        assert(captures(r.roots@[0],rs[0],base));
        assert forall|i:int| 0<=i<objects.len() implies {
            let o=#[trigger] r.objects@[i];
            &&& o.body@==objects@[i].body@ && o.flags==objects@[i].encoding.flag()
            &&& o.start as int==base as int+72+begin.len()+extent(objects@,i as nat)
            &&& r.media.image().subrange(o.start as int+72,o.start as int+72+o.body.len())==o.body@
        } by {
            assert(captures(r.objects@[i],os[i],base));
            assert(extent(objects@,(i+1) as nat)==extent(objects@,i as nat)+72+objects@[i].body.len());
        }
    }
    r
}
}
