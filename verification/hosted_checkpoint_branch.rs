//! Project per-child ownership and field boundaries from the complete branch reader.
use crate::{
    ObjectId,ObjectReference,checkpoint_branch::{self as branch,RowsError},
    checkpoint_child::ChildError,checkpoint_key_field as key,
};
use vstd::prelude::*;

verus! {

proof fn after_start(path:Seq<usize>,i:nat)
    requires i < path.len(), forall|j:int| 0 <= j < path.len()-1 ==> #[trigger] path[j] <= #[trigger] path[j+1],
    ensures path[0] <= path[i as int],
    decreases i,
{
    if i > 0 { after_start(path,(i-1) as nat); let j = i as int - 1; assert(path[j] <= path[j+1]); }
}

fn child_at(bytes:&[u8],refs:&[ObjectReference],start:usize,level:u16,count:usize,index:usize)
    -> (out:Option<(ObjectId,Vec<u8>,u16)>)
    requires index < count,
    ensures out matches Some(row) ==> index < refs.len() && row.0 == refs@[index as int].fields().1 &&
        row.2 as int+1 == level && exists|s:usize| start <= s &&
        s as int+4+key::length(bytes@,s as int)+24 <= bytes.len() &&
        row.1@ == bytes@.subrange(s as int+4,s as int+4+key::length(bytes@,s as int)),
{
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let (end,mut rows) = match branch::read(bytes,refs,level,count,start,accept) {
        Ok(pair) => pair, Err(_) => return None,
    };
    let ghost path = choose|p:Seq<usize>| #[trigger] branch::layout(bytes@,refs@,start,end,level,rows@,p,accept);
    proof {
        assert forall|i:int| 0 <= i < rows.len() implies #[trigger] path[i] <= #[trigger] path[i+1] by {
            assert(branch::row_at(bytes@,refs@,i,path[i],path[i+1],level,rows@[i],accept));
        }
        after_start(path,index as nat);
        assert(branch::row_at(bytes@,refs@,index as int,path[index as int],path[index as int+1],level,rows@[index as int],accept));
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    }
    let row = rows.swap_remove(index);
    Some((row.object,row.lower_bound,row.level))
}

fn refused_first(bytes:&[u8],refs:&[ObjectReference],start:usize,level:u16,count:usize)
    -> (out:Result<branch::ParsedRows,(usize,RowsError<()>)>)
    requires count > 0, level > 0, start as int + 4 + key::length(bytes@,start as int) <= bytes.len(),
    ensures out matches Err(pair) && pair.0 as int == start as int + 4 + key::length(bytes@,start as int)
        && pair.1 matches RowsError::Child(ChildError::InvalidKey(_)),
{
    let deny = |_:&[u8]| -> (r:Result<(),()>) ensures r is Err { Err(()) };
    let out = branch::read(bytes,refs,level,count,start,deny);
    proof {
        if out is Ok {
            let pair = out->Ok_0;
            let pos = choose|p:Seq<usize>| #[trigger] branch::layout(bytes@,refs@,start,pair.0,level,pair.1@,p,deny);
            assert(branch::row_at(bytes@,refs@,0,pos[0],pos[1],level,pair.1@[0],deny));
        } else {
            let pair = out->Err_0;
            let (rows,pos,s) = choose|rows:Seq<crate::checkpoint_range::Child<ObjectId,crate::checkpoint_totals::NodeTotals>>,pos:Seq<usize>,s:usize|
                rows.len() < count && #[trigger] branch::layout(bytes@,refs@,start,s,level,rows,pos,deny) &&
                (pair.1 matches RowsError::Child(reason) && crate::checkpoint_child::failure(bytes@,refs@,rows.len() as usize,s as int,pair.0 as int,deny,reason));
            if rows.len() > 0 { assert(branch::row_at(bytes@,refs@,0,pos[0],pos[1],level,rows[0],deny)); }
            assert(s == start);
        }
    }
    out
}

// A genuine two-child branch uses two consecutive fields and two different slots.
fn written_pair(first:&[u8],second:&[u8],totals:crate::checkpoint_totals::NodeTotals,left:ObjectId,right:ObjectId)
    -> (out:Result<branch::ParsedRows,(usize,RowsError<()>)>)
    requires first.len() <= u32::MAX,second.len() <= u32::MAX,
        first.len() as int + second.len() + 56 <= usize::MAX,totals.entries > 0,
    ensures out matches Ok(pair) && pair.0 as int == first.len()+second.len()+56 &&
        pair.1.len() == 2 && pair.1@[0].object == left && pair.1@[1].object == right &&
        pair.1@[0].lower_bound@ == first@ && pair.1@[1].lower_bound@ == second@,
{
    let mut bytes = Vec::new();
    let mut refs = Vec::new();
    key::append(&mut bytes,first);
    totals.append(&mut bytes);
    let middle = bytes.len();
    key::append(&mut bytes,second);
    totals.append(&mut bytes);
    let left_label = crate::checkpoint_reference::label(crate::checkpoint_reference::Relation::Child,0).unwrap();
    let right_label = crate::checkpoint_reference::label(crate::checkpoint_reference::Relation::Child,1).unwrap();
    refs.push(ObjectReference::owns(left_label,left));
    refs.push(ObjectReference::owns(right_label,right));
    let ghost mid = middle as int;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(0,4) =~= crate::storage_words::word32(first.len() as u32));
        assert(bytes@.subrange(mid,mid+4) =~= crate::storage_words::word32(second.len() as u32));
        key::encoded_length(bytes@,0,first.len() as u32);
        key::encoded_length(bytes@,mid,second.len() as u32);
        assert(bytes@.subrange(4,4+first.len()) =~= first@);
        assert(bytes@.subrange(mid+4,mid+4+second.len()) =~= second@);
        assert(bytes@.subrange(mid-24,mid) =~= totals.wire());
        assert(bytes@.subrange(mid+4+second.len(),bytes.len() as int) =~= totals.wire());
    }
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let out = branch::read(&bytes,&refs,1,2,0,accept);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        if out is Err {
            let pair = out->Err_0;
            let (rows,pos,s) = choose|rows:Seq<crate::checkpoint_range::Child<ObjectId,crate::checkpoint_totals::NodeTotals>>,pos:Seq<usize>,s:usize|
                rows.len() < 2 && #[trigger] branch::layout(bytes@,refs@,0,s,1,rows,pos,accept) &&
                (pair.1 matches RowsError::Child(reason) && crate::checkpoint_child::failure(bytes@,refs@,rows.len() as usize,s as int,pair.0 as int,accept,reason));
            if rows.len() > 0 { assert(branch::row_at(bytes@,refs@,0,pos[0],pos[1],1,rows[0],accept)); }
            assert(s == if rows.len()==0 { 0 } else {middle});
            let summary = s as int + 4 + key::length(bytes@,s as int) as int;
            if pair.1 matches RowsError::Child(ChildError::Empty) {
                let empty = choose|t:crate::checkpoint_totals::NodeTotals| t.entries == 0 && crate::storage_fields::at(bytes@,summary,#[trigger] t.wire());
                crate::hosted_checkpoint_totals::same(empty,totals);
            }
        } else {
            let pair = out->Ok_0;
            let pos = choose|p:Seq<usize>| #[trigger] branch::layout(bytes@,refs@,0,pair.0,1,pair.1@,p,accept);
            assert(branch::row_at(bytes@,refs@,0,pos[0],pos[1],1,pair.1@[0],accept));
            assert(branch::row_at(bytes@,refs@,1,pos[1],pos[2],1,pair.1@[1],accept));
        }
    }
    out
}
}
