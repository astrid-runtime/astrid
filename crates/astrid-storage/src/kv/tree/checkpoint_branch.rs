//! The branch reader uses a single byte cursor and indexes the same reference list throughout.
use super::{
    ObjectId, ObjectReference,
    checkpoint_child::{self, ChildError},
    checkpoint_page,
    checkpoint_range::Child,
    checkpoint_summary::{self, FinishError},
    checkpoint_totals::NodeTotals,
};
#[cfg(verus_keep_ghost)]
use super::{checkpoint_key_field as key, checkpoint_reference as edge};
use vstd::prelude::*;

verus! {

pub(super) enum RowsError<E> { Level, Child(ChildError<E>) }

pub(super) type ParsedRows = (usize, Vec<Child<ObjectId,NodeTotals>>);
type StepError<E> = (usize, RowsError<E>);

pub(super) open spec fn row_at<E,F:Fn(&[u8])->Result<(),E>>(
    bytes:Seq<u8>,refs:Seq<ObjectReference>,idx:int,start:usize,end:usize,
    level:u16,child:Child<ObjectId,NodeTotals>,validate:F,
) -> bool {
    let n = key::length(bytes,start as int) as int;
    let pos = start as int + 4 + n;
    &&& 0 <= idx < refs.len() && idx <= u16::MAX
    &&& end as int == pos + 24 && child.level as int + 1 == level
    &&& child.lower_bound@ == bytes.subrange(start as int+4,pos)
    &&& child.totals.entries > 0 && crate::storage_fields::at(bytes,pos,child.totals.wire())
    &&& refs[idx].fields() == (edge::wire(edge::Relation::Child,idx as usize),child.object,super::ReferenceKind::Owns)
    &&& exists|k:&[u8],r:Result<(),E>| k@ == child.lower_bound@ && r is Ok && #[trigger] validate.ensures((k,),r)
}

pub(super) open spec fn layout<E,F:Fn(&[u8])->Result<(),E>>(
    bytes:Seq<u8>,refs:Seq<ObjectReference>,first:usize,end:usize,level:u16,
    rows:Seq<Child<ObjectId,NodeTotals>>,positions:Seq<usize>,validate:F,
) -> bool {
    &&& positions.len() == rows.len()+1 && positions[0] == first && positions.last() == end
    &&& forall|i:int| 0 <= i < rows.len() ==> row_at(bytes,refs,i,positions[i],positions[i+1],level,#[trigger] rows[i],validate)
}

pub(super) fn read<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],
    level:u16,count:usize,start:usize,validate:F)
    -> (out:Result<ParsedRows,StepError<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures out matches Ok(pair) ==> level > 0 && pair.1.len() == count &&
        exists|pos:Seq<usize>| #[trigger] layout(bytes@,refs@,start,pair.0,level,pair.1@,pos,validate),
    out matches Err(pair) ==> if level == 0 { pair.0 == start && pair.1 is Level } else {
        exists|rows:Seq<Child<ObjectId,NodeTotals>>,pos:Seq<usize>,s:usize|
            rows.len() < count && #[trigger] layout(bytes@,refs@,start,s,level,rows,pos,validate) &&
            (pair.1 matches RowsError::Child(reason) && checkpoint_child::failure(
                bytes@,refs@,rows.len() as usize,s as int,pair.0 as int,validate,reason))
    },
{
    let fetch = |s:usize,i:usize| -> (out:Result<(usize,Vec<u8>,ObjectId,NodeTotals),StepError<E>>)
        ensures out matches Ok(row) ==> ({
            let child = Child {level:level.saturating_sub(1),lower_bound:row.1,object:row.2,totals:row.3};
            level > 0 ==> row_at(bytes@,refs@,i as int,s,row.0,level,child,validate)
        }),
        out matches Err(pair) ==> (pair.1 matches RowsError::Child(reason) && checkpoint_child::failure(
            bytes@,refs@,i,s as int,pair.0 as int,validate,reason)),
    {
        let mut end = s;
        match checkpoint_child::read(bytes,&mut end,refs,i,validate) {
            Ok((key,id,totals)) => Ok((end,key,id,totals)),
            Err(e) => Err((end,RowsError::Child(e))),
        }
    };
    let out = checkpoint_page::children(level,count,start,fetch,|| -> (out:StepError<E>) ensures out.0 == start && out.1 is Level { (start,RowsError::Level) });
    proof {
        if out is Ok {
            let pair = out->Ok_0;
            let pos = choose|pos:Seq<usize>| #[trigger] checkpoint_page::decoded(pair.1@,pos,start,pair.0,level,fetch);
            assert forall|i:int| 0 <= i < pair.1.len() implies
                row_at(bytes@,refs@,i,pos[i],pos[i+1],level,#[trigger] pair.1@[i],validate) by {
                let row = pair.1@[i];
                assert(fetch.ensures((pos[i],i as usize),Ok((pos[i+1],row.lower_bound,row.object,row.totals))));
            }
            assert(layout(bytes@,refs@,start,pair.0,level,pair.1@,pos,validate));
        } else if level > 0 {
            let e = out->Err_0;
            let (rows,pos,s) = choose|rows:Seq<Child<ObjectId,NodeTotals>>,pos:Seq<usize>,s:usize|
                rows.len() < count && #[trigger] checkpoint_page::decoded(rows,pos,start,s,level,fetch) &&
                fetch.ensures((s,rows.len() as usize),Err(e));
            assert forall|i:int| 0 <= i < rows.len() implies
                row_at(bytes@,refs@,i,pos[i],pos[i+1],level,#[trigger] rows[i],validate) by {
                let row = rows[i];
                assert(fetch.ensures((pos[i],i as usize),Ok((pos[i+1],row.lower_bound,row.object,row.totals))));
            }
            assert(layout(bytes@,refs@,start,s,level,rows,pos,validate));

        }
    }
    out
}

pub(super) const NODE_MAX_ENTRIES:usize = 64;
pub(super) const MAX_TREE_LEVEL:u16 = 16;

#[derive(Clone,Copy)]
pub(super) struct Header { pub(super) level:u16, pub(super) count:usize, pub(super) totals:NodeTotals }
pub(super) enum DecodeError<E> { Header, Rows(RowsError<E>), Finish(FinishError) }

pub(super) open spec fn rejected_row<E,F:Fn(&[u8])->Result<(),E>>(
    bytes:Seq<u8>,refs:Seq<ObjectReference>,index:usize,start:usize,end:usize,validate:F,reason:RowsError<E>,
) -> bool {
    reason matches RowsError::Child(e) && checkpoint_child::failure(bytes,refs,index,start as int,end as int,validate,e)
}

impl Header {
    pub(super) open spec fn valid(&self, references:usize) -> bool {
        0 < self.level <= MAX_TREE_LEVEL && 2 <= self.count <= NODE_MAX_ENTRIES && self.count == references
    }

    pub(super) open spec fn outcome<E,F:Fn(&[u8])->Result<(),E>>(self,bytes:&[u8],refs:&[ObjectReference],start:usize,validate:F,
        out:Result<checkpoint_page::Branch<ObjectId,NodeTotals>,DecodeError<E>>) -> bool {
        &&& (out matches Err(DecodeError::Header)) == !self.valid(refs.len())
        &&& out matches Err(DecodeError::Rows(reason)) ==> exists|prior:Seq<Child<ObjectId,NodeTotals>>,pos:Seq<usize>,s:usize,end:usize|
                prior.len() < self.count && #[trigger] layout(bytes@,refs@,start,s,self.level,prior,pos,validate) &&
                #[trigger] rejected_row(bytes@,refs@,prior.len() as usize,s,end,validate,reason)
        &&& out matches Err(DecodeError::Finish(reason)) ==> exists|rows:Vec<Child<ObjectId,NodeTotals>>,pos:Seq<usize>,end:usize|
                rows.len() == self.count && #[trigger] layout(bytes@,refs@,start,end,self.level,rows@,pos,validate) &&
                checkpoint_summary::finished(end,bytes.len(),self.level,rows,self.totals) == Err(reason)
        &&& out matches Ok(b) ==> ({
                &&& b.level == self.level && b.totals == self.totals && b.children.len() == self.count
                &&& checkpoint_summary::ordered(b.children@,self.count as nat)
                &&& checkpoint_summary::counts(b.children@,self.count as nat) ==
                    (b.totals.entries as nat,b.totals.logical_bytes as nat,b.totals.quota_bytes as nat)
                &&& exists|pos:Seq<usize>| #[trigger] layout(bytes@,refs@,start,bytes.len(),b.level,b.children@,pos,validate)
            })
    }

    pub(super) fn decode<E,F:Fn(&[u8])->Result<(),E>+Copy>(self,bytes:&[u8],refs:&[ObjectReference],start:usize,validate:F)
        -> (out:Result<checkpoint_page::Branch<ObjectId,NodeTotals>,DecodeError<E>>)
        requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
        ensures self.outcome(bytes,refs,start,validate,out),
    {
        if self.level == 0 || self.level > MAX_TREE_LEVEL || self.count < 2 ||
            self.count > NODE_MAX_ENTRIES || self.count != refs.len() { return Err(DecodeError::Header); }
        let (end,children) = match read(bytes,refs,self.level,self.count,start,validate) {
            Ok(pair) => pair, Err((_end,reason)) => {
                let ghost (prior,pos,s) = choose|r:Seq<Child<ObjectId,NodeTotals>>,p:Seq<usize>,s:usize|
                    r.len() < self.count && #[trigger] layout(bytes@,refs@,start,s,self.level,r,p,validate) &&
                    (reason matches RowsError::Child(e) && checkpoint_child::failure(bytes@,refs@,r.len() as usize,s as int,_end as int,validate,e));
                assert(rejected_row(bytes@,refs@,prior.len() as usize,s,_end,validate,reason));
                return Err(DecodeError::Rows(reason));
            },
        };
        let ghost pos = choose|p:Seq<usize>| #[trigger] layout(bytes@,refs@,start,end,self.level,children@,p,validate);
        match checkpoint_summary::finish(end,bytes.len(),self.level,children,self.totals) {
            Ok(branch) => {
                assert(end == bytes.len());
                assert(branch == checkpoint_page::Branch {level:self.level,children,totals:self.totals});
                assert(checkpoint_summary::ordered(children@,self.count as nat));
                assert(layout(bytes@,refs@,start,bytes.len(),branch.level,branch.children@,pos,validate));
                Ok(branch)
            },
            Err(e) => {
                assert(checkpoint_summary::finished(end,bytes.len(),self.level,children,self.totals) == Err(e));
                Err(DecodeError::Finish(e))
            },
        }
    }
}
}
