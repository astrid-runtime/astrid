//! Assemble the persisted leaf only after every byte, owning reference and advertised total agrees.
use super::{
    ObjectReference,
    checkpoint_branch::{Header, NODE_MAX_ENTRIES},
    checkpoint_entries as entries,
    checkpoint_header::{self as header, Kind},
    checkpoint_leaf_summary as summary,
    checkpoint_page::Leaf,
    checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
};
#[cfg(verus_keep_ghost)]
use super::checkpoint_entries::Row;
use vstd::prelude::*;

verus! {
pub(super) enum Error<E> { Prefix(header::Error), Count, Entries(entries::Error<E>), Summary(summary::Error) }
pub(super) type DecodedLeaf = Leaf<ValueSlot,NodeTotals>;

pub(super) open spec fn body<E,F:Fn(&[u8])->Result<(),E>>(
    bytes:Seq<u8>,refs:Seq<ObjectReference>,start:usize,h:Header,validate:F,out:Result<DecodedLeaf,Error<E>>,
) -> bool {
    &&& (out matches Err(Error::Count)) == (h.count == 0 || h.count > NODE_MAX_ENTRIES)
    &&& match out {
        Ok(leaf) => ({
            &&& leaf.entries.len() == h.count && leaf.totals == h.totals
            &&& summary::ordered(leaf.entries@,h.count as nat) && h.totals.entries == h.count
            &&& summary::usage(leaf.entries@,h.count as nat) == (h.totals.logical_bytes as nat,h.totals.quota_bytes as nat)
            &&& exists|p:Seq<(usize,usize)>| #[trigger] entries::layout(bytes,refs,start,(bytes.len() as usize,refs.len() as usize),leaf.entries@,p,validate)
        }),
        Err(Error::Entries(e)) => exists|rows:Seq<Row>,p:Seq<(usize,usize)>,s:(usize,usize)|
            #[trigger] entries::stopped(bytes,refs,start,h.count,validate,rows,p,s,e),
        Err(Error::Summary(e)) => exists|rows:Vec<Row>,p:Seq<(usize,usize)>| rows.len() == h.count &&
            #[trigger] entries::layout(bytes,refs,start,(bytes.len() as usize,refs.len() as usize),rows@,p,validate) && summary::outcome(rows,h.totals) == Err(e),
        Err(Error::Count) => true,
        Err(Error::Prefix(_)) => false,
    }
}

pub(super) fn read<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],validate:F)
    -> (out:Result<DecodedLeaf,Error<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures match out {
        Err(Error::Prefix(e)) => header::prefix_error(bytes@,Kind::Leaf,e),
        _ => exists|h:Header,s:usize| #[trigger] header::present(bytes@,Kind::Leaf,h,s) &&
            body(bytes@,refs@,s,h,validate,out),
    },
{
    let (start,h) = match header::read(bytes,Kind::Leaf) {Ok(pair)=>pair,Err(e)=>return Err(Error::Prefix(e))};
    let out = decode_body(bytes,refs,start,h,validate);
    assert(header::present(bytes@,Kind::Leaf,h,start));
    out
}

fn decode_body<E,F:Fn(&[u8])->Result<(),E>+Copy>(bytes:&[u8],refs:&[ObjectReference],start:usize,h:Header,validate:F)
    -> (out:Result<DecodedLeaf,Error<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures body(bytes@,refs@,start,h,validate,out),
{
    let ghost terminal = (bytes@.len() as usize,refs@.len() as usize);
    assert(terminal == (bytes.len(),refs.len()));
    let out = if h.count == 0 || h.count > NODE_MAX_ENTRIES {Err(Error::Count)}
    else {
        match entries::read(bytes,refs,start,h.count,validate) {
            Err(e)=>{
                let ghost (rows,p,s) = choose|rows:Seq<Row>,p:Seq<(usize,usize)>,s:(usize,usize)|
                    #[trigger] entries::stopped(bytes@,refs@,start,h.count,validate,rows,p,s,e);
                assert(body(bytes@,refs@,start,h,validate,Err(Error::Entries(e))));
                Err(Error::Entries(e))
            },
            Ok(rows)=>{
                let ghost path = choose|p:Seq<(usize,usize)>| #[trigger] entries::layout(bytes@,refs@,start,(bytes.len(),refs.len()),rows@,p,validate);
                match summary::finish(rows,h.totals) {
                    Ok(leaf)=>{
                        assert(leaf.entries == rows && leaf.totals == h.totals);
                        assert(summary::ordered(rows@,h.count as nat));
                        assert(summary::usage(rows@,h.count as nat) == (h.totals.logical_bytes as nat,h.totals.quota_bytes as nat));
                        assert(entries::layout(bytes@,refs@,start,terminal,leaf.entries@,path,validate));
                        assert(exists|p:Seq<(usize,usize)>| #[trigger] entries::layout(bytes@,refs@,start,terminal,leaf.entries@,p,validate));
                        assert(body(bytes@,refs@,start,h,validate,Ok(leaf)));
                        Ok(leaf)
                    },
                    Err(e)=>{
                        assert(summary::outcome(rows,h.totals) == Err(e));
                        assert(entries::layout(bytes@,refs@,start,terminal,rows@,path,validate));
                        assert(exists|r:Vec<Row>,p:Seq<(usize,usize)>| r.len()==h.count &&
                            #[trigger] entries::layout(bytes@,refs@,start,terminal,r@,p,validate) &&
                            summary::outcome(r,h.totals) == Err(e));
                        assert(body(bytes@,refs@,start,h,validate,Err(Error::Summary(e))));
                        Err(Error::Summary(e))
                    },
                }
            },
        }
    };
    assert(body(bytes@,refs@,start,h,validate,out));
    out
}
}
