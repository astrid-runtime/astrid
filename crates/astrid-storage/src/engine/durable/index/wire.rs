//! Decode checkpoint snapshots and apply ordered deltas to the recovered index.
#[cfg(verus_keep_ghost)]
use super::ObjectId;
use super::{
    ArenaLocation, IndexState, arena_index, checkpoint_key as key,
    root_wire::{self, Scheme},
};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{btree::btree_map_inv, iter::IteratorSpec},
};

verus! {

pub(super) enum Error { Field(key::Error), TailTag, Count }

fn key_error(e:key::Error) -> Error {Error::Field(e)}

fn field(e:root_wire::ReadError) -> Error {Error::Field(key::Error::Read(e))}

pub(super) open spec fn length(bytes:Seq<u8>,at:int) -> u64 {
    vstd::bytes::spec_u64_from_le_bytes(bytes.subrange(at,at+8))
}

pub(super) open spec fn rows_start(start:int,tail:Option<ArenaLocation>) -> int {
    start+4+8+1+(if tail.is_some() {48int} else {0int})+8
}

pub(super) open spec fn snapshot_at(bytes:Seq<u8>,start:int,end:int,scheme:Scheme,s:IndexState) -> bool {
    let rows=rows_start(start,s.arena_tail);
    let count=length(bytes,rows-8);
    &&& 0<=start && end<=bytes.len() && end==rows+count as int*key::ROW_LEN
    &&& key::scheme_at(bytes,start,scheme) && s.arena_len==length(bytes,start+4)
    &&& match s.arena_tail {
        None=>bytes[start+12]==0,
        Some(loc)=>bytes[start+12]==1 && loc.wire()==bytes.subrange(start+13,start+61),
    }
    &&& key::mapped(bytes,rows,count as nat,s.objects@)
    &&& forall|i:int| 0<=i<count ==> #[trigger] key::ordered_row(bytes,rows,i,scheme)
}

#[verifier::opaque]
pub(super) open spec fn ordered(bytes:Seq<u8>,start:int,count:u64,scheme:Scheme) -> bool {
    forall|i:int| 0<=i<count ==> #[trigger] key::ordered_row(bytes,start,i,scheme)
}

pub(super) open spec fn readable(bytes:Seq<u8>,start:int,scheme:Scheme) -> bool {
    let tag=bytes[start+12];
    let rows=start+21+(if tag==1 {48int} else {0int});
    let count=length(bytes,rows-8);
    &&& key::scheme_at(bytes,start,scheme) && start+13<=bytes.len() && (tag==0 || tag==1)
    &&& rows<=bytes.len() && count<=usize::MAX
    &&& ordered(bytes,rows,count,scheme)
}

pub(super) open spec fn snapshot_end(bytes:Seq<u8>,start:int) -> int {
    let rows=start+21+(if bytes[start+12]==1 {48int} else {0int});
    rows+length(bytes,rows-8) as int*key::ROW_LEN
}

pub(super) fn snapshot(bytes:&[u8],cursor:&mut usize,scheme:Scheme) -> (out:Result<IndexState,Error>)
    requires *old(cursor)<=bytes.len(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures out matches Ok(s) ==> btree_map_inv(&s.objects) && *final(cursor)<=bytes.len() &&
        snapshot_at(bytes@,*old(cursor) as int,*final(cursor) as int,scheme,s) &&
        *final(cursor) as int==snapshot_end(bytes@,*old(cursor) as int),
        readable(bytes@,*old(cursor) as int,scheme) ==> out.is_ok(),
{
    let ghost start=*cursor as int;
    key::read_scheme(bytes,cursor,scheme).map_err(key_error)?;
    let arena_len=u64::from_le_bytes(root_wire::fixed::<8>(bytes,cursor).map_err(field)?);
    let tag=root_wire::fixed::<1>(bytes,cursor).map_err(field)?;
    assert(bytes@.subrange(start+12,start+13)[0]==bytes@[start+12]);
    assert(tag[0]==bytes@[start+12]);
    let arena_tail=match tag[0] {
        0=>None,
        1=>{
            let raw=root_wire::take(bytes,cursor,ArenaLocation::ENCODED_LEN).map_err(field)?;
            let Some(loc)=ArenaLocation::decode(raw) else {assert(false);unreachable!()};
            Some(loc)
        }
        _=>return Err(Error::TailTag),
    };
    let word=root_wire::fixed::<8>(bytes,cursor).map_err(field)?;
    let Ok(count)=usize::try_from(u64::from_le_bytes(word)) else {return Err(Error::Count);};
    let ghost row_start=*cursor;
    assert(word@==bytes@.subrange(row_start as int-8,row_start as int));
    assert(row_start as int==rows_start(start,arena_tail));
    assert(row_start as int==start+21+(if bytes@[start+12]==1 {48int} else {0int}));
    assert(count as int==length(bytes@,row_start as int-8));
    proof {if readable(bytes@,start,scheme) {
        assert(ordered(bytes@,row_start as int,count as u64,scheme));
        reveal(ordered);
        assert forall|i:int| 0<=i<count implies #[trigger] key::ordered_row(bytes@,row_start as int,i,scheme) by {};
    }}
    let objects=key::rows(bytes,cursor,count,scheme).map_err(key_error)?;
    proof {
        assert(row_start as int==rows_start(start,arena_tail));
        if count>0 {
            let last=count as int-1;
            assert(key::ordered_row(bytes@,row_start as int,last,scheme));
        }
    }
    let state=IndexState{arena_len,arena_tail,objects};
    assert(*cursor<=bytes.len());
    assert(state.arena_len==length(bytes@,start+4));
    assert(snapshot_at(bytes@,start,*cursor as int,scheme,state));
    Ok(state)
}

pub(super) const SNAPSHOT_RECORD:u8=1;
pub(super) const DELTA_RECORD:u8=2;

pub(super) enum RecordError<E> { Wire(Error), Invalid(E), MissingSnapshot, RepeatedSnapshot, Unknown, Trailing, Discontinuous, Backwards, Remap }

pub(super) open spec fn delta_at(bytes:Seq<u8>,start:int,end:int,scheme:Scheme,prior:IndexState,
    additions:IndexState,next:IndexState) -> bool {
    let rows=start+76;
    let count=length(bytes,rows-8);
    &&& start>=0 && end<=bytes.len() && end==rows+count as int*key::ROW_LEN
    &&& key::scheme_at(bytes,start,scheme) && prior.arena_len==length(bytes,start+4)
    &&& next.arena_len==additions.arena_len==length(bytes,start+12) && prior.arena_len<=next.arena_len
    &&& next.arena_tail==additions.arena_tail && (next.arena_tail matches Some(loc) && loc.wire()==bytes.subrange(start+20,start+68))
    &&& key::mapped(bytes,rows,count as nat,additions.objects@)
    &&& forall|i:int| 0<=i<count ==> #[trigger] key::ordered_row(bytes,rows,i,scheme)
    &&& prior.objects@.submap_of(next.objects@) && additions.objects@.submap_of(next.objects@)
    &&& next.objects@.dom()==prior.objects@.dom().union(additions.objects@.dom())
}

fn delta<E,V:FnOnce(&IndexState)->Result<(),E>>(bytes:&[u8],cursor:&mut usize,scheme:Scheme,
    mut prior:IndexState,validate:V) -> (out:Result<IndexState,RecordError<E>>)
    requires *old(cursor)<=bytes.len(),btree_map_inv(&prior.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|s:&IndexState| #[trigger] validate.requires((s,)),
    ensures out matches Ok(next) ==> btree_map_inv(&next.objects) &&
        exists|add:IndexState| #[trigger] validate.ensures((&add,),Ok(())) &&
            delta_at(bytes@,*old(cursor) as int,*final(cursor) as int,scheme,prior,add,next),
{
    let ghost base=prior;
    let ghost start=*cursor as int;
    key::read_scheme(bytes,cursor,scheme).map_err(|e| RecordError::Wire(Error::Field(e)))?;
    let previous=u64::from_le_bytes(root_wire::fixed::<8>(bytes,cursor).map_err(|e| RecordError::Wire(field(e)))?);
    let arena_len=u64::from_le_bytes(root_wire::fixed::<8>(bytes,cursor).map_err(|e| RecordError::Wire(field(e)))?);
    if previous!=prior.arena_len {return Err(RecordError::Discontinuous);}
    if arena_len<previous {return Err(RecordError::Backwards);}
    let raw=root_wire::take(bytes,cursor,ArenaLocation::ENCODED_LEN).map_err(|e| RecordError::Wire(field(e)))?;
    let Some(loc)=ArenaLocation::decode(raw) else {assert(false);unreachable!()};
    let word=root_wire::fixed::<8>(bytes,cursor).map_err(|e| RecordError::Wire(field(e)))?;
    let Ok(count)=usize::try_from(u64::from_le_bytes(word)) else {return Err(RecordError::Wire(Error::Count));};
    let objects=key::rows(bytes,cursor,count,scheme).map_err(|e| RecordError::Wire(Error::Field(e)))?;
    let additions=IndexState{arena_len,arena_tail:Some(loc),objects};
    validate(&additions).map_err(|e| RecordError::Invalid(e))?;
    let mut it=additions.objects.iter();
    let ghost seq=it.remaining();
    let ghost mut i=0int;
    loop
        invariant btree_map_inv(&prior.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            seq.len()==additions.objects.len(),0<=i<=seq.len(),it.remaining()==seq.skip(i as int),
            seq.unref().to_set()==additions.objects@.kv_pairs(),
            base.objects@.submap_of(prior.objects@),
            prior.objects@.dom().subset_of(base.objects@.dom().union(additions.objects@.dom())),
            forall|j:int| 0<=j<i ==> prior.objects@.kv_pairs().contains(#[trigger] seq.unref()[j]),
        ensures i==seq.len(),base.objects@.submap_of(prior.objects@),btree_map_inv(&prior.objects),
            prior.objects@.dom().subset_of(base.objects@.dom().union(additions.objects@.dom())),
            forall|j:int| 0<=j<i ==> prior.objects@.kv_pairs().contains(#[trigger] seq.unref()[j]),
        decreases additions.objects.len()-i,
    {
        let Some((id,at))=it.next() else {assert(i==seq.len());break;};
        assert(seq.unref()[i as int]==(*id,*at));
        proof {seq.unref().to_set_ensures();assert(additions.objects@.kv_pairs().contains((*id,*at)));}
        let ghost before=prior.objects@;
        if !arena_index::restore_location(&mut prior.objects,*id,*at) {return Err(RecordError::Remap);}
        assert(it.remaining() =~= seq.skip(i as int+1));
        proof {
            assert(prior.objects@==before.insert(*id,*at));
            assert(prior.objects@.contains_key(*id) && prior.objects@[*id]==*at);
            assert(prior.objects@.kv_pairs().contains((*id,*at)));
            assert(before.submap_of(prior.objects@));
            assert forall|k:ObjectId| #[trigger] base.objects@.contains_key(k) implies
                prior.objects@.contains_key(k) && prior.objects@[k]==base.objects@[k] by {
                assert(before.contains_key(k) && before[k]==base.objects@[k]);
            }
            assert forall|j:int| 0<=j<i+1 implies prior.objects@.kv_pairs().contains(#[trigger] seq.unref()[j]) by {
                if j<i {let (k,v)=seq.unref()[j];assert(before.kv_pairs().contains((k,v)));assert(prior.objects@[k]==v);assert(prior.objects@.contains_key(k));}
                else {assert(j==i);assert(seq.unref()[j]==(*id,*at));}
            }
            i=i+1;
        };
    }
    proof {
        seq.unref().to_set_ensures();
        assert forall|k:ObjectId| #[trigger] additions.objects@.contains_key(k) implies prior.objects@.contains_key(k) &&
            prior.objects@[k]==additions.objects@[k] by {
            let pair=(k,additions.objects@[k]);
            assert(seq.unref().to_set().contains(pair));
            let j=choose|j:int| 0<=j<seq.len() && #[trigger] seq.unref()[j]==pair;
            assert(prior.objects@.kv_pairs().contains(seq.unref()[j]));
        }
        assert(prior.objects@.dom() =~= base.objects@.dom().union(additions.objects@.dom()));
    }
    prior.arena_len=arena_len;
    prior.arena_tail=Some(loc);
    assert(delta_at(bytes@,start,*cursor as int,scheme,base,additions,prior));
    Ok(prior)
}

/// A snapshot creates state once. Only a delta can extend it. Both records must
/// consume their whole physical payload before the caller can retain the state.
pub(super) fn record<E,V>(bytes:&[u8],prior:Option<IndexState>,scheme:Scheme,validate:V)
    -> (out:Result<IndexState,RecordError<E>>)
    where V:FnOnce(&IndexState)->Result<(),E>,
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|s:&IndexState| #[trigger] validate.requires((s,)),
        prior matches Some(old) ==> btree_map_inv(&old.objects),
    ensures out matches Ok(s) ==> match prior {
        None=>bytes.len()>0 && bytes@[0]==SNAPSHOT_RECORD && snapshot_at(bytes@,1,bytes.len() as int,scheme,s) &&
            btree_map_inv(&s.objects) && validate.ensures((&s,),Ok(())),
        Some(old)=>bytes.len()>0 && bytes@[0]==DELTA_RECORD && btree_map_inv(&s.objects) &&
            exists|add:IndexState| #[trigger] validate.ensures((&add,),Ok(())) && delta_at(bytes@,1,bytes.len() as int,scheme,old,add,s),
    },
        prior.is_none() && bytes.len()>0 && bytes@[0]==SNAPSHOT_RECORD && readable(bytes@,1,scheme) &&
            snapshot_end(bytes@,1)==bytes.len() &&
            (forall|s:&IndexState,r:Result<(),E>| #[trigger] validate.ensures((s,),r) ==> r.is_ok()) ==> out.is_ok(),
        bytes.len()>0 && bytes@[0]==SNAPSHOT_RECORD && prior.is_some() ==> out matches Err(RecordError::RepeatedSnapshot),
        bytes.len()>0 && bytes@[0]==DELTA_RECORD && prior.is_none() ==> out matches Err(RecordError::MissingSnapshot),
        bytes.len()>0 && bytes@[0]!=SNAPSHOT_RECORD && bytes@[0]!=DELTA_RECORD ==> out matches Err(RecordError::Unknown),
{
    let mut cursor=0;
    let tag=root_wire::fixed::<1>(bytes,&mut cursor).map_err(|e| RecordError::Wire(field(e)))?;
    assert(bytes@.subrange(0,1)[0]==bytes@[0]);
    let state=match (tag[0],prior) {
        (SNAPSHOT_RECORD,None)=>{
            let state=snapshot(bytes,&mut cursor,scheme).map_err(|e| RecordError::Wire(e))?;
            validate(&state).map_err(|e| RecordError::Invalid(e))?;
            state
        }
        (DELTA_RECORD,Some(old))=>{
            delta(bytes,&mut cursor,scheme,old,validate)?
        }
        (SNAPSHOT_RECORD,Some(_))=>return Err(RecordError::RepeatedSnapshot),
        (DELTA_RECORD,None)=>return Err(RecordError::MissingSnapshot),
        _=>return Err(RecordError::Unknown),
    };
    if cursor!=bytes.len() {return Err(RecordError::Trailing);}
    Ok(state)
}

}
