//! Follow one fresh token marker from its arena writer to cold admission.
use super::*;
use crate::{arena_frame as frame, root_wire::Scheme, verified_record as record};

verus! {

fn select_payload<'a>(v:&'a Vec<u8>) -> (out:&'a [u8]) ensures out@==v@ {v.as_slice()}

closed spec fn appended_marker<I:FnOnce(&crate::ObjectRecord)->crate::ObjectId>(
    prior:Seq<u8>,image:Seq<u8>,address:Seq<u8>,id:crate::ObjectId,loc:frame::ArenaLocation,identify:I) -> bool {
    let at=loc.offset as int+frame::WIDTH;
    &&& loc.offset>=prior.len()
    &&& at+loc.payload_len<=image.len()
    &&& image.take(prior.len() as int)==prior
    &&& image.subrange(at+8,at+40)==id.digest()
    &&& crate::hosted_delta_mutation::marker_bytes(
        crate::hosted_journal_history::component_bytes(image,loc),address)
    &&& exists|r:&crate::ObjectRecord| #[trigger] identify.ensures((r,),id) &&
        r.contents().2==crate::hosted_journal_history::component_bytes(image,loc)
}

/// Recover the stored ID, byte count and data directly from the object encoder's
/// wire equation. References after the data may have any canonical length.
pub(crate) proof fn encoded_fields(image:Seq<u8>,loc:frame::ArenaLocation,body:Seq<u8>,
    scheme:Scheme,id:crate::ObjectId,r:crate::ObjectRecord)
    requires {
        let f=r.contents();
        body==scheme.algorithm@+scheme.construction@+seq![32u8,0u8,0u8,0u8]+id.digest()+
            record::header_wire(f.0,f.1,f.5)+record::payload_wire(f.4,f.2,f.3.len() as usize)+
            record::reference_prefix(f.3,f.3.len(),scheme)
    }, body.len()==loc.payload_len,loc.offset as int+frame::WIDTH+loc.payload_len<=image.len(),
        image.subrange(loc.offset as int+frame::WIDTH,loc.offset as int+frame::WIDTH+loc.payload_len)==body,
    ensures image.subrange(loc.offset as int+frame::WIDTH+8,loc.offset as int+frame::WIDTH+40)==id.digest(),
        crate::hosted_journal_history::component_bytes(image,loc)==r.contents().2,
{
    let at=loc.offset as int+frame::WIDTH;
    let fields=r.contents();
    let identity=scheme.algorithm@+scheme.construction@+seq![32u8,0u8,0u8,0u8]+id.digest();
    let prefix=identity+record::header_wire(fields.0,fields.1,fields.5);
    let length=prefix.len() as int+8;
    let start=prefix.len() as int+24;
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    assert(identity.len()==40 && prefix.len()==45);
    assert(body.subrange(8,40) =~= id.digest());
    assert(image.subrange(at+8,at+40) =~= image.subrange(at,at+loc.payload_len).subrange(8,40));
    assert(body.subrange(length,length+8) =~= vstd::bytes::spec_u64_to_le_bytes(fields.2.len() as u64));
    assert(body.subrange(start,start+fields.2.len()) =~= fields.2);
    assert(fields.2.len()<=body.len());
    assert(record::u64_field(body,length)==fields.2.len());
}

/// Install the selected payload in a submitted arena batch. The returned interval
/// and file prefix refer to the actual bytes sent to the canonical file.
pub(crate) fn append_payload<S:frame::BatchFile,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    file:&mut S,payload:Vec<u8>,mut batch:Vec<Vec<u8>>,selected:usize,hash:H,
) -> (out:Result<frame::ArenaLocation,frame::BatchError<S::Error>>)
    requires old(file).image().len()<=u64::MAX,selected<batch.len(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ARENA_MAGIC,n,b)),
    ensures final(file).target()==old(file).target(),out matches Ok(loc) ==> {
        let at=loc.offset as int+frame::WIDTH;
        &&& loc.offset>=old(file).image().len() && at+loc.payload_len<=final(file).image().len()
        &&& loc.payload_len==payload.len()
        &&& final(file).image().take(old(file).image().len() as int)==old(file).image()
        &&& final(file).image().subrange(at,at+loc.payload_len)==payload@
    },
{
    let ghost payload_bytes=payload@;
    batch.set(selected,payload);
    let batch=batch.as_slice();
    let select=select_payload;
    let ghost prior=file.image();
    let rows=frame::append_batch(file,batch,select,hash,frame::ARENA_MAGIC,frame::FRAME_VERSION,
        (Vec::new(),Vec::new()))?;
    let loc=rows[selected];
    proof {
        let base=prior.len() as u64;
        let encoded=choose|bytes:Seq<u8>| file.image()==prior+bytes &&
            #[trigger] frame::packed(batch,select,hash,base,frame::ARENA_MAGIC,frame::FRAME_VERSION,
                Seq::empty(),bytes,rows@);
        crate::hosted_acknowledged_root::packed_row(batch,select,hash,base,frame::ARENA_MAGIC,
            frame::FRAME_VERSION,Seq::empty(),encoded,rows@,selected as int);
        let start=loc.offset as int-base;
        let body=choose|b:&[u8]| #[trigger] select.ensures((&batch@[selected as int],),b) &&
            b.len()==loc.payload_len && hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),loc.checksum) &&
            encoded.subrange(start,start+52+loc.payload_len)==frame::header_bytes(frame::ARENA_MAGIC,
                frame::FRAME_VERSION,loc.payload_len,loc.checksum)+b@;
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(file.image().take(prior.len() as int) =~= prior);
        let at=loc.offset as int+52;
        let header=frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum);
        assert(header.len()==52);
        assert(body@==payload_bytes);
        assert(encoded.subrange(start+52,start+52+loc.payload_len) =~=
            encoded.subrange(start,start+52+loc.payload_len).skip(52));
        assert(file.image().subrange(at,at+loc.payload_len) =~= encoded.subrange(start+52,start+52+loc.payload_len));
        assert(file.image().subrange(at,at+loc.payload_len)==payload_bytes);
    }
    Ok(loc)
}

/// Follow a production marker record through canonical encoding and arena append.
/// Neighbouring frames and the pre-existing file prefix have independent contents.
#[verifier::rlimit(20)]
fn append_token_marker<S:frame::BatchFile,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    I:FnOnce(&crate::ObjectRecord)->crate::ObjectId>(
    file:&mut S,scheme:Scheme,key:Vec<u8>,previous:Option<crate::ObjectId>,
    depth:u64,used:u64,totals:crate::checkpoint_totals::NodeTotals,
    batch:Vec<Vec<u8>>,selected:usize,identify:I,hash:H,
) -> (out:Result<(crate::ObjectId,frame::ArenaLocation),frame::BatchError<S::Error>>)
    requires key.len()<=u32::MAX && key.len()+51<=isize::MAX && depth<u64::MAX &&
        used+key.len()+1<=u64::MAX, old(file).image().len()<=u64::MAX, selected<batch.len(),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ARENA_MAGIC,n,b)),
    ensures final(file).target()==old(file).target(),
        out matches Ok((id,loc)) ==> appended_marker(old(file).image(),final(file).image(),key@,id,loc,identify),
{
    let (marker,_)=crate::hosted_delta_mutation::written_marker(key,previous,depth,used,totals);
    let id=identify(&marker);
    let payload=record::encode(scheme,id,&marker).unwrap();
    let ghost prior=file.image();
    let loc=append_payload(file,payload,batch,selected,hash)?;
    proof {
        encoded_fields(file.image(),loc,payload@,scheme,id,marker);
        let data=marker.contents().2;
        assert(identify.ensures((&marker,),id));
        assert(exists|r:&crate::ObjectRecord| #[trigger] identify.ensures((r,),id) &&
            r.contents().2==crate::hosted_journal_history::component_bytes(file.image(),loc));
        assert(crate::hosted_delta_mutation::marker_bytes(data,key@));
        assert(loc.offset>=prior.len());
        assert(appended_marker(prior,file.image(),key@,id,loc,identify));
    }
    Ok((id,loc))
}

enum MarkerRestart<M,P,E> {
    AlreadyIndexed(crate::ArenaLocation),
    Unavailable,
    DifferentComponent,
    Recovered(M,crate::hosted_recovered_header::RecoveredGraph<P>,Result<Admission,ReopenError<E>>),
}

/// Write a fresh marker, install its returned location, read the recovered owner
/// from that arena, and run admission if its KV edge selects the written object.
fn append_then_reopen_marker<File:crate::arena_frame::BatchFile,Hasher,Identity,Media:crate::positional_read::Media,Open,P:Ord+Copy,S,B,V,T,W,E,KE,Check,Select,Fail,M,I,K,D,A,R,C,F>(
    file:&mut File,batch:Vec<Vec<u8>>,selected:usize,previous:Option<crate::ObjectId>,depth:u64,used:u64,
    totals:crate::checkpoint_totals::NodeTotals,hash:Hasher,identify:Identity,open:Open,media_id:Ghost<spec_fn(Media)->(int,Seq<u8>)>,version:crate::ObjectFormatVersion,
    index:&mut std::collections::BTreeMap<crate::ObjectId,crate::ArenaLocation>,
    history:&std::collections::BTreeMap<P,(crate::RootState,u64)>,candidate:std::collections::BTreeMap<P,crate::RootState>,
    wave:u64,limit:u64,scheme:crate::root_wire::Scheme,
    owner:P,kind:Marker,target:Id,single_use:bool,other:&(crate::memo_projection::Projection<B>,V),
    select:Select,fail:Fail,measure:M,start:I,values:(K,D),translate:A,rev_read:R,used_read:C,legacy:F)
    -> (out:Result<(crate::ObjectId,crate::ArenaLocation,MarkerRestart<Media,P,E>),frame::BatchError<File::Error>>)
    where Hasher:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,Identity:Fn(&crate::ObjectRecord)->[u8;32]+Copy,
        Open:FnOnce(&File)->Media,
        Check:Fn(&[u8])->Option<KE>+Copy,Select:Fn(crate::ObjectId)->Check,Fail:Fn(crate::ObjectId)->E,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,I:FnOnce(&P)->S,
        K:Fn(S,Option<crate::ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        D:Fn(S,&crate::checkpoint_value::ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(crate::ObjectId,crate::delta_totals::ApplyError<E>)->E,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires vstd::laws_cmp::obeys_cmp::<P>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<P>(),
        selected<batch.len(),old(file).image().len()<=u64::MAX,depth<u64::MAX,used as int+65<=u64::MAX,
        vstd::std_specs::btree::btree_map_inv(old(index)),vstd::std_specs::btree::btree_map_inv(history),
        vstd::std_specs::btree::btree_map_inv(&candidate),
        forall|magic:[u8;8],n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|f:&File| #[trigger] open.requires((f,)),
        forall|f:&File,m:Media| #[trigger] open.ensures((f,),m) ==> m.image()==f.image() && (media_id@)(m)==f.target(),
        forall|id:crate::ObjectId| #[trigger] select.requires((id,)),
        forall|id:crate::ObjectId| #[trigger] fail.requires((id,)),
        forall|id:crate::ObjectId,check:Check,b:&[u8]| #[trigger] select.ensures((id,),check) ==> #[trigger] check.requires((b,)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|p:&P,tree:Option<crate::ObjectId>| *p==owner ==> #[trigger] measure.requires((p,tree)),
        forall|p:&P| *p==owner ==> #[trigger] start.requires((p,)),
        forall|s:S,t:Option<crate::ObjectId>,key:&Vec<u8>| #[trigger] values.0.requires((s,t,key)),
        forall|s:S,v:&crate::checkpoint_value::ValueSlot| #[trigger] values.1.requires((s,v)),
        forall|id:crate::ObjectId,e:crate::delta_totals::ApplyError<E>| #[trigger] translate.requires((id,e)),
        checkpoint::readable(rev_read),checkpoint::readable(used_read),other.0.overlay.ordered_snapshot(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures final(file).target()==old(file).target(), vstd::std_specs::btree::btree_map_inv(final(index)),
        out.is_err() ==> final(index)@==old(index)@,
        out matches Ok((id,loc,state)) ==> {
            let image=final(file).image();
            let at=loc.offset as int+frame::WIDTH;
            &&& loc.offset>=old(file).image().len() && at+loc.payload_len<=image.len()
            &&& image.take(old(file).image().len() as int)==old(file).image()
            &&& image.subrange(at+8,at+40)==id.digest()
            &&& forall|spelling:Seq<u8>| #[trigger] marker_key::spells(target@,spelling) ==>
                crate::hosted_delta_mutation::marker_bytes(crate::hosted_journal_history::component_bytes(image,loc),
                    ns_bytes(kind)+seq![0u8]+spelling)
            &&& match state {
                MarkerRestart::AlreadyIndexed(earlier)=>old(index)@.get(id)==Some(earlier) && final(index)@==old(index)@,
                _=>!old(index)@.contains_key(id) && final(index)@==old(index)@.insert(id,loc),
            }
            &&& state matches MarkerRestart::Recovered(media,graph,outcome) ==> {
                &&& (media_id@)(media)==old(file).target() && media.image()==image
                &&& graph.owner==owner && history@.contains_key(owner) && graph.root==history@[owner].0
                &&& graph.from_arena(media.image(),final(index)@,scheme,version) && graph.component==Some(id)
                &&& graph.records@.contains_key(id) &&
                    graph.records@[id].contents().2==crate::hosted_journal_history::component_bytes(media.image(),loc)
                &&& outcome matches Ok(decision) ==> (kind is Revoked ==> decision is Revoked) && (single_use ==> !(decision is Allowed))
            }
        },
{
    let (name,text)=kind.address(marker_key::encode(&target));
    let ns=name.as_bytes();
    let address=crate::encoding::composite(ns,&text);
    proof {
        reveal_strlit("caps:used");reveal_strlit("caps:revoked");
        vstd::string::is_ascii_spec_bytes("caps:used");vstd::string::is_ascii_spec_bytes("caps:revoked");
        assert(ns@==ns_bytes(kind));
    }
    let object_id=|r:&crate::ObjectRecord| crate::ObjectId::new(identify(r));
    let (id,loc)=append_token_marker(file,scheme,address,previous,depth,used,
        totals,batch,selected,object_id,hash)?;
    proof {
        assert forall|spelling:Seq<u8>| #[trigger] marker_key::spells(target@,spelling) implies
            crate::hosted_delta_mutation::marker_bytes(crate::hosted_journal_history::component_bytes(file.image(),loc),
                ns_bytes(kind)+seq![0u8]+spelling) by {marker_key::unique_text(target@,text@,spelling);}
    }
    if let Some(earlier)=index.get(&id) {return Ok((id,loc,MarkerRestart::AlreadyIndexed(*earlier)));}
    index.insert(id,loc);
    let media=open(file);
    let format=crate::indexed_frame::Format{magic:crate::arena_frame::ARENA_MAGIC,
        version:crate::arena_frame::FRAME_VERSION,limit,scheme};
    let Some(graph)=crate::hosted_recovered_header::recovered_header(index,history,&media,wave,format,hash,
        identify,candidate,&owner,version) else {return Ok((id,loc,MarkerRestart::Unavailable))};
    let Some(component)=graph.component else {return Ok((id,loc,MarkerRestart::DifferentComponent))};
    if !component.same(&id) {return Ok((id,loc,MarkerRestart::DifferentComponent));}
    proof {crate::hosted_journal_history::component_contents(media.image(),(id,loc),scheme,graph.records@[id]);}
    let ghost path=seq![id];
    let decision=reopen_loaded_marker(&graph,Ghost(path),version,Ghost(media.image()),Ghost(index@),scheme,kind,target,single_use,other,
        select,fail,measure,start,values,translate,rev_read,used_read,legacy);
    Ok((id,loc,MarkerRestart::Recovered(media,graph,decision)))
}

}
