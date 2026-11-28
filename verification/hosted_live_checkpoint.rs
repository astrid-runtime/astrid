//! Follow a live WAL checkpoint from retained roots to physical journal frames and cold replay.
use crate::{owner_codec::Owner, root_transition::PreparedRoot, root_wire};
use std::collections::BTreeMap;
use vstd::laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq};
use vstd::pervasive::obeys_clone_eq;
use vstd::prelude::*;
use vstd::std_specs::{btree::btree_map_inv, iter::IteratorSpec};

verus! {
type WriterRoots=BTreeMap<u64,crate::RootState>;

fn journal_bytes<'a>(row:&'a &[u8]) -> (bytes:&'a [u8])
    ensures bytes@==(*row)@,
{ *row }

spec fn folded_journal<H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    image:Seq<u8>,base:int,rows:Seq<crate::arena_frame::ArenaLocation>,i:int,
    bytes:Seq<u8>,hash:H,magic:[u8;8],version:u16) -> bool {
    let loc=rows[i];
    let start=loc.offset as int;
    let end=start+crate::arena_frame::WIDTH+bytes.len();
    &&& start==if i==0 {base} else {rows[i-1].offset as int+crate::arena_frame::WIDTH+rows[i-1].payload_len}
    &&& end<=image.len() && loc.payload_len==bytes.len()
    &&& crate::arena_frame::hashed(hash,magic,bytes,loc.checksum)
    &&& image.subrange(start,end)==crate::arena_frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+bytes
}

/// Fold an accepted root after an arbitrary pending prefix. The last physical frame
/// contains that transition's journal; the receipt names its replacement at the same owner.
fn retained_root_frame<S:crate::arena_frame::BatchFile,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    root:PreparedRoot<u64,crate::RootState>,initial_pending:Vec<PreparedRoot<u64,crate::RootState>>,
    initial_writer:WriterRoots,file:&mut S,hash:H,magic:[u8;8],version:u16)
    -> (out:Result<(WriterRoots,crate::RootState,Vec<crate::arena_frame::ArenaLocation>),crate::arena_frame::BatchError<S::Error>>)
    requires btree_map_inv(&initial_writer),obeys_cmp::<u64>(),obeys_cmp_concrete_eq::<u64>(),obeys_clone_eq::<u64>(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
        old(file).image().len()<=u64::MAX,
    ensures final(file).target()==old(file).target(),
        out matches Ok((roots,ack,rows)) ==> {
            let desc=root.binding();
            &&& ack==desc.2 && roots@==initial_writer@.insert(desc.0,ack)
            &&& final(file).image().take(old(file).image().len() as int)==old(file).image()
            &&& rows@.last().offset as int+crate::arena_frame::WIDTH+rows@.last().payload_len==final(file).image().len()
            &&& rows.len()==initial_pending.len()+1
            &&& forall|i:int| 0<=i<rows.len() ==> #[trigger] folded_journal(final(file).image(),old(file).image().len() as int,
                rows@,i,initial_pending@.push(root)[i].binding().3@,hash,magic,version)
            &&& final(file).image().len()>=old(file).image().len()+crate::arena_frame::WIDTH+desc.3.len()
            &&& final(file).image().skip(final(file).image().len()-desc.3.len())==desc.3@
        },
{
    use crate::arena_frame as frame;
    let mut pending=initial_pending;
    let mut writer=initial_writer;
    let ghost prior=pending@;
    root.retain(&mut pending);
    let (ack,())=root.publish(&mut writer,|_,_,_| (),|_,_,_| ());
    let project=PreparedRoot::<u64,crate::RootState>::journal_bytes;
    let retained=pending.as_slice();
    let payloads=crate::group_frontier::journals(retained,project);
    let select=journal_bytes;
    let input=payloads.as_slice();
    let rows=frame::append_batch(file,input,select,hash,magic,version,(Vec::new(),Vec::new()))?;
    proof {
        let base=old(file).image().len() as u64;
        let bytes=choose|b:Seq<u8>| file.image()==old(file).image()+b &&
            #[trigger] frame::packed(input,select,hash,base,magic,version,Seq::empty(),b,rows@);
        assert forall|j:int| 0<=j<rows.len() implies #[trigger] folded_journal(file.image(),base as int,rows@,j,
            prior.push(root)[j].binding().3@,hash,magic,version) by {
            crate::hosted_acknowledged_root::packed_row(input,select,hash,base,magic,version,Seq::empty(),bytes,rows@,j);
            assert(project.ensures((&retained@[j],),payloads@[j]));
            if j<prior.len() {assert(pending@.drop_last()[j]==pending@[j]);}
            let loc=rows@[j];
            let at=loc.offset as int-base;
            let end=at+frame::WIDTH+loc.payload_len;
            let selected=choose|b:&[u8]| #[trigger] select.ensures((&input@[j],),b) && b.len()==loc.payload_len &&
                hash.ensures((magic,loc.payload_len,b),loc.checksum) &&
                bytes.subrange(at,end)==frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+b@;
            assert(frame::hashed(hash,magic,selected@,loc.checksum));
            assert(file.image().subrange(loc.offset as int,end+base) =~= bytes.subrange(at,end));
        }
        reveal_with_fuel(frame::packed,2);
        let i=rows.len() as int-1;
        let loc=rows@[i];
        let start=loc.offset as int-base;
        assert(project.ensures((&retained@[i],),payloads@[i]));
        assert(input@[i]@==root.binding().3@);
        let body=choose|b:&[u8]| #[trigger] select.ensures((&input@[i],),b) &&
            b.len()==loc.payload_len && hash.ensures((magic,loc.payload_len,b),loc.checksum) &&
            bytes==bytes.take(start)+frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+b@;
        assert(frame::hashed(hash,magic,root.binding().3@,loc.checksum));
        let prefix=bytes.take(start);
        assert(file.image().take(old(file).image().len() as int) =~= old(file).image());
        assert(file.image() =~= old(file).image()+prefix+frame::header_bytes(magic,version,loc.payload_len,loc.checksum)+body@);
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(frame::header_bytes(magic,version,loc.payload_len,loc.checksum).len()==frame::WIDTH);
        assert(file.image().skip(file.image().len()-root.binding().3.len()) =~= root.binding().3@);
    };
    Ok((writer,ack,rows))
}

spec fn selected_wire(s:crate::root_transition::SelectedRoot<u64>,names:spec_fn(u64)->Seq<u8>,scheme:root_wire::Scheme) -> Seq<u8> {
    let (key,prior,next)=s.binding();
    crate::journal_transition::wire(names(key),scheme,prior,next)
}

/// Prepare an arbitrary retained prefix with the production journal encoder at each owner.
fn prepare_checkpoint_prefix<N:Fn(&u64)->Owner+Copy>(selected:Vec<crate::root_transition::SelectedRoot<u64>>,
    name:N,names:Ghost<spec_fn(u64)->Seq<u8>>,scheme:root_wire::Scheme)
    -> (out:Vec<PreparedRoot<u64,crate::RootState>>)
    requires forall|p:&u64| #[trigger] name.requires((p,)),
        forall|p:&u64,o:Owner| #[trigger] name.ensures((p,),o) ==> o.bytes()==(names@)(*p),
    ensures out.len()==selected.len(),forall|i:int| 0<=i<selected.len() ==> {
        let b=(#[trigger] out@[i]).binding();
        &&& (b.0,b.1,b.2)==selected@[i].binding()
        &&& b.3@==selected_wire(selected@[i],names@,scheme)
    },
{
    let mut out:Vec<PreparedRoot<u64,crate::RootState>>=Vec::with_capacity(selected.len());
    let mut it=selected.into_iter();
    loop
        invariant out.len()<=selected.len(),it.remaining()==selected@.skip(out.len() as int),
            forall|p:&u64| #[trigger] name.requires((p,)),
            forall|p:&u64,o:Owner| #[trigger] name.ensures((p,),o) ==> o.bytes()==(names@)(*p),
            forall|i:int| 0<=i<out.len() ==> {
                let b=(#[trigger] out@[i]).binding();
                &&& (b.0,b.1,b.2)==selected@[i].binding()
                &&& b.3@==selected_wire(selected@[i],names@,scheme)
            },
        decreases selected.len()-out.len(),
    {
        let Some(s)=it.next() else {assert(out.len()==selected.len());return out;};
        assert(s==selected@[out.len() as int]);
        let prepared=s.encode_journal(scheme,|p:&u64| -> (bytes:Vec<u8>)
            ensures bytes@==(names@)(*p),bytes.len()<u64::MAX, {name(p).encode()}).unwrap();
        out.push(prepared);
        assert(it.remaining() =~= selected@.skip(out.len() as int));
    }
}

enum LiveFoldError<F,E> {
    Append(crate::arena_frame::BatchError<F>),
    Barrier(E),
    Retirement(crate::group_frontier::CheckpointError<E>),
    FrameLimit,
}

/// Retire the actual WAL bound to the newly appended journal. The selected media
/// must expose that file's target and pending bytes before the barrier starts.
fn checkpoint_retained_roots<File,Hash,S,Bind,A,R,J,V,Seek,Read,Open,Name,Key>(selected:crate::root_transition::SelectedRoot<u64>,
    earlier:Vec<crate::root_transition::SelectedRoot<u64>>,writer:WriterRoots,file:&mut File,hash:Hash,
    bind:Bind,arena:A,representations:R,roots:J,volume:V,rewind:Seek,
    owner:Owner,scheme:root_wire::Scheme,names:Ghost<spec_fn(u64)->Seq<u8>>,name_of:Name,key_of:Key,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    open:Open,limit:u64,restart:&mut BTreeMap<u64,(crate::RootState,u64)>)
    -> (out:Result<(S,WriterRoots,crate::RootState,Vec<crate::arena_frame::ArenaLocation>,bool),LiveFoldError<File::Error,S::Error>>)
    where File:crate::arena_frame::BatchFile, Hash:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        S:crate::group_frontier::ResizeWal,Bind:FnOnce(&File)->S,
        A:FnOnce(S)->Result<S,S::Error>,R:FnOnce(S)->Result<S,S::Error>,J:FnOnce(S)->Result<S,S::Error>,
        V:FnOnce(S)->Result<S,S::Error>,Seek:FnOnce(S)->Result<S,S::Error>,
        Read:crate::frame_repair::FrameReader,Open:FnOnce(&S,u64)->(Read,u64),
        Name:Fn(&u64)->Owner+Copy,Key:FnOnce(Owner)->u64,
    requires btree_map_inv(&writer),obeys_cmp::<u64>(),obeys_cmp_concrete_eq::<u64>(),obeys_clone_eq::<u64>(),
        old(file).image().len()<=u64::MAX,btree_map_inv(old(restart)),
        forall|p:&u64| #[trigger] name_of.requires((p,)),
        forall|p:&u64,o:Owner| #[trigger] name_of.ensures((p,),o) ==> o.bytes()==(names@)(*p),
        forall|o:Owner| #[trigger] name_of.ensures((&selected.binding().0,),o) ==> o.bytes()==owner.bytes(),
        forall|o:Owner| o.bytes()==owner.bytes() ==> #[trigger] key_of.requires((o,)),
        forall|o:Owner,k:u64| o.bytes()==owner.bytes() && #[trigger] key_of.ensures((o,),k) ==> k==selected.binding().0,
        forall|b:&[u8],sum:[u8;32]| #[trigger] hash.ensures((crate::arena_frame::ROOT_MAGIC,b.len() as u64,b),sum) ==> sum==(digest@)(b@),
        forall|s:S,at:u64| #[trigger] open.requires((&s,at)),
        forall|s:S,at:u64,pair:(Read,u64)| #[trigger] open.ensures((&s,at),pair) ==>
            pair.0.target()==s.roots_target() && pair.0.position()==at && pair.1==pair.0.image().len() &&
            s.canonical_stable().get(crate::recovery_barrier::Target::Roots)==Some(pair.0.image()),
        forall|r:Read,at:int,e:Read::Error| r.target()==old(file).target() ==> !#[trigger] r.failed(at,52,e),
        forall|r:Read,at:int,e:Read::Error| r.target()==old(file).target() ==> !#[trigger] r.failed(at,
            crate::journal_transition::wire(owner.bytes(),scheme,selected.binding().1,selected.binding().2).len() as u64,e),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ROOT_MAGIC,n,b)),
        forall|f:&File| #[trigger] bind.requires((f,)),
        forall|f:&File,s:S| #[trigger] bind.ensures((f,),s) ==> s.roots_target()==f.target() &&
            s.wal_target()!=s.roots_target() && s.arena_target()!=s.roots_target() &&
            s.canonical_pending().get(crate::recovery_barrier::Target::Roots)==Some(f.image()) &&
            crate::hosted_recovery_barrier::live_phases(s,arena,representations,roots,volume,rewind),
    ensures btree_map_inv(final(restart)),out.is_err() ==> final(restart)@==old(restart)@,
        out matches Err(LiveFoldError::FrameLimit) ==> crate::journal_transition::wire(owner.bytes(),scheme,
            selected.binding().1,selected.binding().2).len()>limit,
        out matches Ok((media,installed,ack,rows,accepted)) ==> {
        let (key,prior,next)=selected.binding();
        let image=media.canonical_stable()[crate::recovery_barrier::Target::Roots];
        let loc=rows@.last();
        let actual=old(restart)@.get(key);
        &&& media.canonical_stable().contains_key(crate::recovery_barrier::Target::Roots)
        &&& media.roots_target()==old(file).target() && media.wal_target()!=media.roots_target()
        &&& media.stable_image()==Seq::<u8>::empty() && image==final(file).image()
        &&& ack==next && installed@==writer@.insert(key,ack)
        &&& image.take(old(file).image().len() as int)==old(file).image()
        &&& loc.offset as int+crate::arena_frame::WIDTH+loc.payload_len==image.len()
        &&& rows.len()==earlier.len()+1
        &&& forall|i:int| 0<=i<earlier.len() ==> #[trigger] folded_journal(image,old(file).image().len() as int,
            rows@,i,selected_wire(earlier@[i],names@,scheme),hash,crate::arena_frame::ROOT_MAGIC,crate::arena_frame::FRAME_VERSION)
        &&& folded_journal(image,old(file).image().len() as int,rows@,earlier.len() as int,
            crate::journal_transition::wire(owner.bytes(),scheme,prior,next),hash,crate::arena_frame::ROOT_MAGIC,crate::arena_frame::FRAME_VERSION)
        &&& accepted==((match actual {None=>None,Some((r,_))=>Some(r)})==prior &&
            next.generation.value()==match prior {None=>0int,Some(r)=>r.generation.value() as int+1})
        &&& final(restart)@==if accepted {old(restart)@.insert(key,(next,loc.offset))} else {old(restart)@}
    },
{
    use crate::arena_frame::{ROOT_MAGIC,FRAME_VERSION};
    let ghost desc=selected.binding();
    let root=selected.encode_journal(scheme,|p:&u64| -> (n:Vec<u8>)
        requires *p==desc.0,ensures n@==owner.bytes(), {name_of(p).encode()}).unwrap();
    let ghost wire=crate::journal_transition::wire(owner.bytes(),scheme,desc.1,desc.2);
    assert(root.binding().3@==wire);
    let (key,prior,next)=root.write_wal(|p:&u64,e:Option<crate::RootState>,r:crate::RootState,_:&Vec<u8>| -> (out:(u64,Option<crate::RootState>,crate::RootState)) ensures out==(*p,e,r), {(*p,e,r)});
    let pending=prepare_checkpoint_prefix(earlier,name_of,names,scheme);
    let (installed,ack,rows)=match retained_root_frame(root,pending,writer,file,hash,ROOT_MAGIC,FRAME_VERSION) {
        Ok(result)=>result,Err(error)=>return Err(LiveFoldError::Append(error)),
    };
    proof {
        let all=pending@.push(root);
        let last=pending.len() as int;
        let base=old(file).image().len() as int;
        assert(folded_journal(file.image(),base,rows@,last,all[last].binding().3@,hash,ROOT_MAGIC,FRAME_VERSION));
        assert(all[last]==root);
        assert forall|i:int| 0<=i<pending.len() implies #[trigger] folded_journal(file.image(),base,rows@,i,
            selected_wire(earlier@[i],names@,scheme),hash,ROOT_MAGIC,FRAME_VERSION) by {
            assert(folded_journal(file.image(),base,rows@,i,all[i].binding().3@,hash,ROOT_MAGIC,FRAME_VERSION));
            assert(all[i]==pending@[i]);
        }
    }
    let initial=bind(file);
    let media=match crate::hosted_recovery_barrier::retire_live_fold(initial,arena,representations,roots,volume,rewind) {
        Ok(Ok(media))=>media,
        Ok(Err(error))=>return Err(LiveFoldError::Retirement(error)),
        Err(error)=>return Err(LiveFoldError::Barrier(error)),
    };
    let loc=rows[rows.len()-1];
    if loc.payload_len>limit {return Err(LiveFoldError::FrameLimit);}
    let (mut reader,end)=open(&media,loc.offset);
    assert(folded_journal(reader.image(),old(file).image().len() as int,rows@,pending.len() as int,wire,hash,ROOT_MAGIC,FRAME_VERSION));
    proof {
        let b=choose|b:&[u8]| b@==wire && #[trigger] hash.ensures((ROOT_MAGIC,wire.len() as u64,b),loc.checksum);
        assert(hash.ensures((ROOT_MAGIC,b.len() as u64,b),loc.checksum));
    }
    let accepted=crate::hosted_acknowledged_root::read_recovered_root(&mut reader,loc.offset,end,limit,
        owner,key,key_of,name_of,scheme,prior,next,hash,digest,Ghost(loc.checksum),restart).unwrap();
    Ok((media,installed,ack,rows,accepted))
}

}
