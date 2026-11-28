//! Compare a published root with restart replay of the same framed journal payload.
use crate::{RootState, arena_frame, journal_history as history, journal_snapshot, journal_transition as journal,
    owner_codec::{self,Owner},root_transition::PreparedRoot,root_wire};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},pervasive::obeys_clone_eq,std_specs::btree::btree_map_inv};

verus! {
/// Parse the production journal header and transition body from the bytes emitted by preparation.
pub(super) fn parse_written(body:&[u8],name:&[u8],scheme:root_wire::Scheme,expected:Option<RootState>,next:RootState)
    -> (out:journal::Record)
    requires name.len()<u64::MAX,body@==journal::wire(name@,scheme,expected,next),
    ensures out.principal@==name@ && out.expected==expected && out.replacement==next,
{
    let mut cursor=0usize;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(name.len() as u64));
    }
    let length=match journal_snapshot::read_header(body,&mut cursor) {
        Ok(journal_snapshot::JournalHeader::Transition(n))=>n,_=>{assert(false);unreached()}
    };
    let prior=match expected {Some(r)=>Some(history::to_wire(r)),None=>None};
    let replacement=history::to_wire(next);
    let ghost pos=8+name.len();
    assert(body@.subrange(8,pos) =~= name@);
    assert(body@.skip(pos) =~= root_wire::prior(prior,scheme)+replacement.wire(scheme));
    assert(root_wire::tail(body@,pos,scheme,prior,replacement));
    let out=match journal::decode(body,&mut cursor,length,scheme) {Ok(r)=>r,Err(_)=>{assert(false);unreached()}};
    proof {
        let (e,r)=choose|e:Option<root_wire::Root>,r:root_wire::Root|
            #[trigger] root_wire::tail(body@,pos,scheme,e,r) && history::represents(r,out.replacement) &&
            match (e,out.expected) {(None,None)=>true,(Some(a),Some(b))=>history::represents(a,b),_=>false};
        root_wire::unique_tail(body@,pos,scheme,e,r,prior,replacement);
        assert(r.generation =~= replacement.generation);assert(r.commit =~= replacement.commit);
        history::unique(r,out.replacement,next);
        if let Some(a)=e {
            assert(a.generation =~= prior.unwrap().generation);assert(a.commit =~= prior.unwrap().commit);
            history::unique(a,out.expected.unwrap(),expected.unwrap());
        }
    }
    out
}

spec fn stored(name:Seq<u8>,scheme:root_wire::Scheme,e:Option<RootState>,r:RootState,magic:[u8;8],version:u16,
    digest:spec_fn([u8;8],u64,Seq<u8>)->[u8;32]) -> Seq<u8> {
    let payload=journal::wire(name,scheme,e,r);
    arena_frame::header_bytes(magic,version,payload.len() as u64,digest(magic,payload.len() as u64,payload))+payload
}

use crate::group_frontier::{JournalContainer,JournalFlush};
enum Failure<E> { Journal(E), Frontier(E) }

/// An arbitrary selected row occupies its own recorded interval in the completed batch.
proof fn packed_row<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    input:&'a [T],select:F,hash:H,base:u64,magic:[u8;8],version:u16,initial:Seq<u8>,encoded:Seq<u8>,
    rows:Seq<arena_frame::ArenaLocation>,i:int)
    requires 0<=i<rows.len(), arena_frame::packed(input,select,hash,base,magic,version,initial,encoded,rows),
    ensures ({
        let loc=rows[i];
        let start=loc.offset as int-base;
        &&& start==if i==0 {initial.len() as int} else {rows[i-1].offset as int-base+52+rows[i-1].payload_len}
        &&& 0<=start && start+52+loc.payload_len<=encoded.len()
        &&& exists|b:&[u8]| #[trigger] select.ensures((&input@[i],),b) && b.len()==loc.payload_len &&
            hash.ensures((magic,loc.payload_len,b),loc.checksum) &&
            encoded.subrange(start,start+52+loc.payload_len)==arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+b@
    }),
    decreases rows.len(),
{
    reveal_with_fuel(arena_frame::packed,3);
    let last=rows.last();
    let begin=last.offset as int-base;
    let earlier=encoded.take(begin);
    let rest=rows.drop_last();
    let body=choose|b:&[u8]| #[trigger] select.ensures((&input@[rows.len()-1],),b) &&
        b.len()==last.payload_len && hash.ensures((magic,last.payload_len,b),last.checksum) &&
        encoded==earlier+arena_frame::header_bytes(magic,version,last.payload_len,last.checksum)+b@;
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    assert(arena_frame::header_bytes(magic,version,last.payload_len,last.checksum).len()==52);
    if i==rows.len()-1 {
        if rest.len()>0 {
            let prev=rest.last();
            let at=prev.offset as int-base;
            let prior=choose|b:&[u8]| #[trigger] select.ensures((&input@[rest.len()-1],),b) &&
                b.len()==prev.payload_len && hash.ensures((magic,prev.payload_len,b),prev.checksum) &&
                earlier==earlier.take(at)+arena_frame::header_bytes(magic,version,prev.payload_len,prev.checksum)+b@;
            assert(arena_frame::header_bytes(magic,version,prev.payload_len,prev.checksum).len()==52);
            assert(begin==at+52+prior.len());
        }
        assert(encoded.subrange(begin,begin+52+last.payload_len) =~= arena_frame::header_bytes(magic,version,last.payload_len,last.checksum)+body@);
    } else {
        packed_row(input,select,hash,base,magic,version,initial,earlier,rest,i);
        let lo=rows[i].offset as int-base;
        let hi=lo+52+rows[i].payload_len;
        assert(rest[i]==rows[i]);
        if i>0 {assert(rest[i-1]==rows[i-1]);}
        let loc=rows[i];
        let earlier_body=choose|b:&[u8]| #[trigger] select.ensures((&input@[i],),b) && b.len()==loc.payload_len &&
            hash.ensures((magic,loc.payload_len,b),loc.checksum) &&
            earlier.subrange(lo,hi)==arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+b@;
        assert(encoded.subrange(lo,hi) =~= earlier.subrange(lo,hi));
        assert(encoded.subrange(lo,hi)==arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+earlier_body@);
    }
}

/// Read one selected transition from an arbitrary completed coalesced write.
fn read_group_transition<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,M:crate::positional_read::Media>(
    input:&'a [T],select:F,hash:H,base:u64,magic:[u8;8],version:u16,initial:Ghost<Seq<u8>>,encoded:&[u8],
    rows:&[arena_frame::ArenaLocation],index:usize,media:&M,name:&[u8],scheme:root_wire::Scheme,
    expected:Option<RootState>,next:RootState,digest:Ghost<spec_fn([u8;8],u64,Seq<u8>)->[u8;32]>)
    -> (out:(journal::Record,Vec<u8>))
    requires index<rows.len(),rows.len()==input.len(),name.len()<u64::MAX,
        arena_frame::packed(input,select,hash,base,magic,version,initial@,encoded@,rows@),
        crate::storage_fields::at(media.image(),base as int,encoded@),
        forall|b:&[u8]| #[trigger] select.ensures((&input@[index as int],),b) ==> b@==journal::wire(name@,scheme,expected,next),
        rows@[index as int].offset as int+52+rows@[index as int].payload_len<=u64::MAX,
        forall|at:u64,err:M::Error| rows@[index as int].offset<=at<rows@[index as int].offset as int+52+rows@[index as int].payload_len
            ==> !#[trigger] media.io_error(at,err),
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
        forall|m:[u8;8],n:u64,b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((m,n,b),sum) ==> sum==(digest@)(m,n,b@),
    ensures out.0.principal@==name@ && out.0.expected==expected && out.0.replacement==next,
        out.1.len()>=52 && out.1@.skip(52)==journal::wire(name@,scheme,expected,next),
        crate::storage_fields::at(media.image(),rows@[index as int].offset as int,stored(name@,scheme,expected,next,magic,version,digest@)),
{
    let loc=rows[index];
    let ghost wire=journal::wire(name@,scheme,expected,next);
    proof {
        packed_row(input,select,hash,base,magic,version,initial@,encoded@,rows@,index as int);
        let start=loc.offset as int-base;
        let body=choose|b:&[u8]| #[trigger] select.ensures((&input@[index as int],),b) && b.len()==loc.payload_len &&
            hash.ensures((magic,loc.payload_len,b),loc.checksum) &&
            encoded@.subrange(start,start+52+loc.payload_len)==arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+b@;
        assert(body@==wire);
        assert(media.image().subrange(loc.offset as int,loc.offset as int+52+loc.payload_len) =~= encoded@.subrange(start,start+52+loc.payload_len));
    }
    assert(52int+loc.payload_len<=encoded.len());
    assert(52int+loc.payload_len<=usize::MAX);
    let length=usize::try_from(loc.payload_len).unwrap();
    let mut bytes=vec![0u8;52+length];
    match crate::positional_read::exact(media,loc.offset,&mut bytes) {Ok(())=>{},Err(_)=>{assert(false);unreached()}}
    let mut header=[0u8;52];
    header.copy_from_slice(&bytes[..52]);
    let body=&bytes[52..];
    assert(header@ =~= arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum));
    assert(body@ =~= wire);
    let valid=crate::hosted_arena_append::physical_frame(&header,magic,version,body,hash,digest);
    assert(valid);
    let record=parse_written(body,name,scheme,expected,next);
    (record,bytes)
}

pub(crate) fn select_body<'a>(body:&'a &'a [u8]) -> (out:&'a [u8]) ensures out@==(*body)@ { *body }

/// The prior recovered history is independent of the live writer. A stale history must reject
/// the otherwise intact frame and leave every owner unchanged.
fn legacy_replay_published<J:crate::group_frontier::JournalSink,M:crate::positional_read::Media,Open:FnOnce(&J)->M,V:FnOnce(&J::Container)->M,A:FnOnce()->Result<(),J::Error>,P:Ord+Copy,K:FnOnce(Owner)->P,N:Fn(&P)->Owner+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(writer:&mut BTreeMap<P,RootState>,
    recovered:&mut BTreeMap<P,(RootState,u64)>,owner:Owner,key:P,key_of:K,name_of:N,expected:Option<RootState>,next:RootState,
    prefix:Vec<u8>,base:u64,magic:[u8;8],version:u16,scheme:root_wire::Scheme,hash:H,sink:&mut J,reopen:Open,reopen_volume:V,advance:A,target:Ghost<spec_fn(M)->(int,Seq<u8>)>,digest:Ghost<spec_fn([u8;8],u64,Seq<u8>)->[u8;32]>)
    -> (out:Result<(RootState,bool,M),Failure<J::Error>>)
    requires btree_map_inv(old(writer)),btree_map_inv(old(recovered)),obeys_cmp::<P>(),
        obeys_cmp_concrete_eq::<P>(),obeys_clone_eq::<P>(),
        name_of.requires((&key,)),forall|o:Owner| #[trigger] name_of.ensures((&key,),o) ==> o.bytes()==owner.bytes(),
        forall|o:Owner| o.bytes()==owner.bytes() ==> #[trigger] key_of.requires((o,)),
        forall|o:Owner,p:P| o.bytes()==owner.bytes() && #[trigger] key_of.ensures((o,),p) ==> p==key,
        base as int==old(sink).pending().len(),old(sink).position()==base,
        forall|s:&J| #[trigger] reopen.requires((s,)),
        forall|s:&J,m:M| #[trigger] reopen.ensures((s,),m) ==> (target@)(m)==s.journal_target() && m.image()==s.durable() &&
            forall|at:u64,err:M::Error| base as int+prefix.len()<=at<base as int+prefix.len()+stored(owner.bytes(),scheme,expected,next,magic,version,digest@).len()
                ==> !#[trigger] m.io_error(at,err),
        advance.requires(()),
        forall|c:&J::Container| #[trigger] reopen_volume.requires((c,)),
        forall|c:&J::Container,m:M| #[trigger] reopen_volume.ensures((c,),m) ==> (target@)(m)==(c.container_id(),c.region_id()) && m.image()==c.durable_image() &&
            forall|at:u64,err:M::Error| base as int+prefix.len()<=at<base as int+prefix.len()+stored(owner.bytes(),scheme,expected,next,magic,version,digest@).len()
                ==> !#[trigger] m.io_error(at,err),
        base as int+prefix.len()+stored(owner.bytes(),scheme,expected,next,magic,version,digest@).len()<=u64::MAX,
        forall|m:[u8;8],n:u64,b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((m,n,b),sum) ==> sum==(digest@)(m,n,b@),
        base as int+prefix.len()<=u64::MAX,prefix.len()+200<=isize::MAX,
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
    ensures ({
        let batch=prefix@+stored(owner.bytes(),scheme,expected,next,magic,version,digest@);
        match out {
            Err(Failure::Journal(e))=>crate::group_frontier::journal_completed(old(sink).journal_calls(),final(sink).journal_calls(),batch,Err(e)),
            _=>exists|receipt:JournalFlush<J::Container>| #[trigger] crate::group_frontier::journal_completed(
                old(sink).journal_calls(),final(sink).journal_calls(),batch,Ok(receipt)) &&
                match out {Err(Failure::Frontier(e))=>advance.ensures((),Err(e)) || (advance.ensures((),Ok(())) &&
                    (receipt matches JournalFlush::AwaitingContainer(c) && c.sync_failed(e))),_=>advance.ensures((),Ok(()))},
        }
    }),
        out.is_err() ==> final(writer)@==old(writer)@ && final(recovered)@==old(recovered)@,
        out matches Ok((ack,applied,media)) ==> ({
        let actual=if old(recovered)@.contains_key(key) {Some(old(recovered)@[key].0)} else {None};
        let generation=match actual {None=>0int,Some(r)=>r.generation.value() as int+1};
        &&& (target@)(media)==old(sink).journal_target()
        &&& crate::storage_fields::at(media.image(),base as int+prefix.len(),
            stored(owner.bytes(),scheme,expected,next,magic,version,digest@))
        &&& ack==next
        &&& final(writer)@==old(writer)@.insert(key,ack)
        &&& applied==(actual==expected && next.generation.value()==generation)
        &&& final(recovered)@==if applied {old(recovered)@.insert(key,(ack,(base as int+prefix.len()) as u64))} else {old(recovered)@}
    }),
{
    let name=owner.encode();
    let encode=|p:&P,e:Option<RootState>,n:RootState| -> (r:Result<Vec<u8>,()>)
        requires *p==key,
        ensures r matches Ok(v) && v@==journal::wire(owner.bytes(),scheme,e,n),
    {Ok(journal::encode(&name_of(p).encode(),scheme,e,n).unwrap())};
    let prepared=PreparedRoot::encode(key,expected,next,encode).unwrap();
    let payload=prepared.write_wal(|_:&P,_:Option<RootState>,_:RootState,bytes:&Vec<u8>| -> (v:Vec<u8>)
        ensures v@==bytes@, {bytes.clone()});
    let start=prefix.len();
    let ghost original=prefix@;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(journal::root(next,scheme).len()==48);
        if let Some(prior)=expected {assert(journal::root(prior,scheme).len()==48);}
        assert(name.len()<=33 && payload.len()<=138);
    }
    let batch=[payload.as_slice()];
    let pick=select_body;
    let (prefix,locations)=match arena_frame::encode_batch(&batch,pick,hash,base,magic,version,(prefix,Vec::new())) {
        Some(out)=>out,None=>{
            proof {
                let (prior,rows,body)=choose|prior:Seq<u8>,rows:Seq<arena_frame::ArenaLocation>,body:&[u8]|
                    #[trigger] arena_frame::refused_at(&batch,pick,hash,base,magic,version,original,prior,rows,body);
                assert(rows.len()==0 && prior==original && body@==payload@);
                assert(false);
            }
            unreached()
        }
    };
    let frame=locations[0];
    proof {
        assert(locations.len()==1);
        packed_row(&batch,pick,hash,base,magic,version,original,prefix@,locations@,0);
        let begin=frame.offset as int-base;
        assert(locations@.drop_last().len()==0);
        assert(arena_frame::packed(&batch,pick,hash,base,magic,version,original,prefix@.take(begin),locations@.drop_last()));
        assert(prefix@.take(begin)==original);
        assert(frame.offset==base as int+start);
    }
    assert(arena_frame::header_bytes(magic,version,frame.payload_len,frame.checksum).len()==52);
    let ghost bytes=stored(owner.bytes(),scheme,expected,next,magic,version,digest@);
    assert(prefix@.skip(start as int) =~= bytes);
    assert(prefix@ =~= original+bytes);
    let ghost prior=sink.pending();
    let receipt=match crate::group_frontier::persist_journal(sink,&prefix) {
        Ok(r)=>r, Err(e)=>return Err(Failure::Journal(e)),
    };
    let completion=match crate::group_frontier::finish_journal(receipt,advance) {
        Ok(c)=>c, Err(e)=>return Err(Failure::Frontier(e)),
    };
    let (ack,_)=prepared.publish(writer,|_,_,_|(),|_,_,_|());
    let media=match completion {None=>reopen(sink),Some(c)=>reopen_volume(&c)};
    assert(media.image()==prior+prefix@);
    assert(media.image().subrange(base as int,base as int+prefix.len()) =~= prefix@);
    let (parsed,observed)=read_group_transition(&batch,pick,hash,base,magic,version,Ghost(original),&prefix,&locations,0,&media,&name,scheme,expected,ack,digest);
    let decode=|n:&[u8]| -> (r:Option<P>)
        requires n@==name@, ensures r==Some(key),
    {Some(key_of(owner_codec::decode(n).unwrap()))};
    let recode=|p:&P| -> (r:Vec<u8>) requires *p==key, ensures r@==owner.bytes(), {name_of(p).encode()};
    let result=parsed.replay(recovered,scheme,frame.offset,&observed[52..],decode,recode);
    Ok((ack,result.is_ok(),media))
}
}
