//! Compare a published root with restart replay of the same framed journal payload.
use crate::{RootState, arena_frame, journal_history as history, journal_snapshot, journal_transition as journal,
    owner_codec::{self,Owner},root_transition::PreparedRoot,root_wire};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},pervasive::obeys_clone_eq,std_specs::btree::btree_map_inv};

verus! {
/// Parse the production journal header and transition body from the bytes emitted by preparation.
fn parse_written(body:&[u8],name:&[u8],scheme:root_wire::Scheme,expected:Option<RootState>,next:RootState)
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

/// The prior recovered history is independent of the live writer. A stale history must reject
/// the otherwise intact frame and leave every owner unchanged.
fn replay_published<M:crate::positional_read::Media,P:Ord+Copy,K:FnOnce(Owner)->P,N:Fn(&P)->Owner+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(writer:&mut BTreeMap<P,RootState>,
    recovered:&mut BTreeMap<P,(RootState,u64)>,owner:Owner,key:P,key_of:K,name_of:N,expected:Option<RootState>,next:RootState,
    mut prefix:Vec<u8>,base:u64,magic:[u8;8],version:u16,scheme:root_wire::Scheme,hash:H,media:&M,digest:Ghost<spec_fn([u8;8],u64,Seq<u8>)->[u8;32]>)
    -> (out:(RootState,bool))
    requires btree_map_inv(old(writer)),btree_map_inv(old(recovered)),obeys_cmp::<P>(),
        obeys_cmp_concrete_eq::<P>(),obeys_clone_eq::<P>(),
        name_of.requires((&key,)),forall|o:Owner| #[trigger] name_of.ensures((&key,),o) ==> o.bytes()==owner.bytes(),
        forall|o:Owner| o.bytes()==owner.bytes() ==> #[trigger] key_of.requires((o,)),
        forall|o:Owner,p:P| o.bytes()==owner.bytes() && #[trigger] key_of.ensures((o,),p) ==> p==key,
        crate::storage_fields::at(media.image(),base as int+prefix.len(),stored(owner.bytes(),scheme,expected,next,magic,version,digest@)),
        base as int+prefix.len()+stored(owner.bytes(),scheme,expected,next,magic,version,digest@).len()<=u64::MAX,
        forall|at:u64,err:M::Error| base as int+prefix.len()<=at<base as int+prefix.len()+stored(owner.bytes(),scheme,expected,next,magic,version,digest@).len()
            ==> !#[trigger] media.io_error(at,err),
        forall|m:[u8;8],n:u64,b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((m,n,b),sum) ==> sum==(digest@)(m,n,b@),
        base as int+prefix.len()<=u64::MAX,prefix.len()+200<=isize::MAX,
        forall|m:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((m,n,b)),
    ensures ({
        let actual=if old(recovered)@.contains_key(key) {Some(old(recovered)@[key].0)} else {None};
        let generation=match actual {None=>0int,Some(r)=>r.generation.value() as int+1};
        &&& out.0==next
        &&& final(writer)@==old(writer)@.insert(key,out.0)
        &&& out.1==(actual==expected && next.generation.value()==generation)
        &&& final(recovered)@==if out.1 {old(recovered)@.insert(key,(out.0,(base as int+prefix.len()) as u64))} else {old(recovered)@}
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
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(journal::root(next,scheme).len()==48);
        if let Some(prior)=expected {assert(journal::root(prior,scheme).len()==48);}
        assert(name.len()<=33 && payload.len()<=138);
    }
    let frame=arena_frame::extend_batch(&mut prefix,base,magic,version,&payload,hash).unwrap();
    let (ack,_)=prepared.publish(writer,|_,_,_|(),|_,_,_|());
    assert(arena_frame::header_bytes(magic,version,frame.payload_len,frame.checksum).len()==52);
    let size=52+payload.len();
    let ghost bytes=stored(owner.bytes(),scheme,expected,next,magic,version,digest@);
    assert(prefix@.skip(start as int) =~= bytes);
    let mut observed=vec![0u8;size];
    match crate::positional_read::exact(media,frame.offset,&mut observed) {
        Ok(())=>{},Err(_)=>{assert(false);unreached()}
    }
    assert(observed@==bytes);
    let mut header=[0u8;52];
    header.copy_from_slice(&observed[..52]);
    let body=&observed[52..];
    assert(header@ =~= arena_frame::header_bytes(magic,version,frame.payload_len,frame.checksum));
    assert(body@ =~= payload@);
    let valid=crate::hosted_arena_append::physical_frame(&header,magic,version,body,hash,digest);
    assert(valid);
    let parsed=parse_written(body,&name,scheme,expected,ack);
    let decode=|n:&[u8]| -> (r:Option<P>)
        requires n@==name@, ensures r==Some(key),
    {Some(key_of(owner_codec::decode(n).unwrap()))};
    let recode=|p:&P| -> (r:Vec<u8>) requires *p==key, ensures r@==owner.bytes(), {name_of(p).encode()};
    let result=parsed.replay(recovered,scheme,frame.offset,body,decode,recode);
    (ack,result.is_ok())
}
}
