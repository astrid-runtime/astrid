//! Decode the declared leaf entries with independent byte and owning-reference cursors.
use super::{
    ObjectReference, checkpoint_key_field as key,
    checkpoint_leaf::Entry,
    checkpoint_value::{self as value, ValueSlot},
};
use vstd::prelude::*;

verus! {
pub(super) enum Error<E> { Key(key::KeyError), Invalid(E), Value(value::Error), Trailing, References }
pub(super) type Row = Entry<ValueSlot>;
type Position = (usize,usize);

pub(super) open spec fn row_at<E,F:Fn(&[u8])->Result<(),E>>(bytes:Seq<u8>,refs:Seq<ObjectReference>,i:int,
    start:Position,end:Position,row:Row,validate:F) -> bool {
    let body = start.0 as int + 4 + key::length(bytes,start.0 as int);
    &&& body <= bytes.len() && row.key@ == bytes.subrange(start.0 as int+4,body)
    &&& exists|k:&[u8],r:Result<(),E>| k@ == row.key@ && r is Ok && #[trigger] validate.ensures((k,),r)
    &&& value::decoded(bytes,body,end.0 as int,refs,start.1,end.1,i as usize,row.value)
}

pub(super) open spec fn layout<E,F:Fn(&[u8])->Result<(),E>>(bytes:Seq<u8>,refs:Seq<ObjectReference>,
    start:usize,end:Position,rows:Seq<Row>,path:Seq<Position>,validate:F) -> bool {
    &&& path.len() == rows.len()+1 && path[0] == (start,0usize) && path.last() == end
    &&& forall|i:int| 0 <= i < rows.len() ==> row_at(bytes,refs,i,path[i],path[i+1],#[trigger] rows[i],validate)
}

pub(super) open spec fn rejected<E,F:Fn(&[u8])->Result<(),E>>(bytes:Seq<u8>,refs:Seq<ObjectReference>,i:usize,
    start:Position,end:usize,validate:F,error:Error<E>) -> bool {
    let body = start.0 as int+4+key::length(bytes,start.0 as int);
    match error {
        Error::Key(e) => key::failure(bytes,start.0 as int,end as int,e),
        Error::Invalid(e) => body == end && body <= bytes.len() && exists|k:&[u8],r:Result<(),E>|
            k@ == bytes.subrange(start.0 as int+4,body) && r == Err(e) && #[trigger] validate.ensures((k,),r),
        Error::Value(e) => body <= bytes.len() && value::failure(bytes,body,end as int,refs,start.1,i,e) &&
            exists|k:&[u8],r:Result<(),E>| k@ == bytes.subrange(start.0 as int+4,body) && r is Ok && #[trigger] validate.ensures((k,),r),
        _ => false,
    }
}

fn one<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],start:Position,i:usize,validate:F)
    -> (out:Result<(Position,Row),(usize,Error<E>)>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures match out {
        Ok(pair) => row_at(bytes@,refs@,i as int,start,pair.0,pair.1,validate),
        Err(pair) => rejected(bytes@,refs@,i,start,pair.0,validate,pair.1),
    },
{
    let (mut cursor,mut edge) = start;
    let field = match key::read(bytes,&mut cursor) {Ok(k)=>k,Err(e)=>return Err((cursor,Error::Key(e)))};
    let checked = validate(field);
    assert(validate.ensures((field,),checked));
    if let Err(e) = checked { return Err((cursor,Error::Invalid(e))); }
    let v = match value::read(bytes,&mut cursor,refs,&mut edge,i) {Ok(v)=>v,Err(e)=>return Err((cursor,Error::Value(e)))};
    let mut key = Vec::with_capacity(field.len());
    key.extend_from_slice(field);
    assert(key@ =~= field@);
    let row = Entry {key,value:v};
    assert(row_at(bytes@,refs@,i as int,start,(cursor,edge),row,validate));
    Ok(((cursor,edge),row))
}

pub(super) open spec fn stopped<E,F:Fn(&[u8])->Result<(),E>>(bytes:Seq<u8>,refs:Seq<ObjectReference>,start:usize,count:usize,
    validate:F,rows:Seq<Row>,p:Seq<Position>,s:Position,e:Error<E>) -> bool {
    &&& layout(bytes,refs,start,s,rows,p,validate)
    &&& match e {
        Error::Trailing => rows.len() == count && s.0 != bytes.len(),
        Error::References => rows.len() == count && s.0 == bytes.len() && s.1 != refs.len(),
        _ => rows.len() < count && exists|end:usize| #[trigger] rejected(bytes,refs,rows.len() as usize,s,end,validate,e),
    }
}

pub(super) fn read<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],start:usize,count:usize,validate:F)
    -> (out:Result<Vec<Row>,Error<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures match out {
        Ok(rows) => rows.len() == count && exists|p:Seq<Position>| #[trigger] layout(bytes@,refs@,start,(bytes.len(),refs.len()),rows@,p,validate),
        Err(e) => exists|rows:Seq<Row>,p:Seq<Position>,s:Position| #[trigger] stopped(bytes@,refs@,start,count,validate,rows,p,s,e),
    },
{
    let mut rows = Vec::with_capacity(count);
    let mut s = (start,0usize);
    let ghost mut path = seq![s];
    while rows.len() < count
        invariant rows.len() <= count, layout(bytes@,refs@,start,s,rows@,path,validate),
            forall|k:&[u8]| #[trigger] validate.requires((k,)),
        decreases count-rows.len(),
    {
        let i = rows.len();
        let (next,row) = match one(bytes,refs,s,i,validate) {
            Ok(pair)=>pair,
            Err((_end,e))=>{
                assert(rejected(bytes@,refs@,i,s,_end,validate,e));
                assert(!(e is Trailing) && !(e is References));
                assert(rows@.len() < count);
                assert(i == rows@.len() as usize);
                assert(rejected(bytes@,refs@,rows@.len() as usize,s,_end,validate,e));
                assert(exists|end:usize| #[trigger] rejected(bytes@,refs@,rows@.len() as usize,s,end,validate,e));
                assert(stopped(bytes@,refs@,start,count,validate,rows@,path,s,e));
                return Err(e);
            },
        };
        let ghost old_rows = rows@;
        let ghost prior = path;
        rows.push(row);
        proof {
            path = path.push(next);
            assert forall|j:int| 0 <= j < rows.len() implies row_at(bytes@,refs@,j,path[j],path[j+1],#[trigger] rows@[j],validate) by {
                if j < i {assert(rows@[j] == old_rows[j] && path[j+1] == prior[j+1]);}
            }
        }
        s = next;
    }
    if s.0 != bytes.len() { assert(stopped(bytes@,refs@,start,count,validate,rows@,path,s,Error::<E>::Trailing)); return Err(Error::Trailing); }
    if s.1 != refs.len() { assert(stopped(bytes@,refs@,start,count,validate,rows@,path,s,Error::<E>::References)); return Err(Error::References); }
    assert(s == (bytes.len(),refs.len()));
    assert(layout(bytes@,refs@,start,(bytes.len(),refs.len()),rows@,path,validate));
    assert(exists|p:Seq<Position>| #[trigger] layout(bytes@,refs@,start,(bytes.len(),refs.len()),rows@,p,validate));
    Ok(rows)
}
}
