//! Ordered merge of staged records and prepared object frames for a WAL transaction.
use super::ObjectId;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{
        btree::{btree_map_inv, increasing_seq},
        cmp::OrdSpec,
        iter::IteratorSpec,
    },
};

verus! {

pub(super) enum Row<'a,A,B> {
    Staged(ObjectId,&'a A),
    Prepared(ObjectId,&'a B),
    Both(ObjectId,&'a A,&'a B),
}

pub(super) enum Input<'a,A,B> { Staged(ObjectId,&'a A), Prepared(ObjectId,&'a B) }

impl<'a,A:PartialEq,B> Row<'a,A,B> {
    /// A prepared encoding may stand for both sources only after decoding to the staged record.
    pub(super) fn resolve<E,D:FnOnce(&B)->Result<A,E>,C:FnOnce(ObjectId)->E>(self,decode:D,collision:C)
        -> (out:Result<Input<'a,A,B>,E>)
        requires vstd::laws_eq::obeys_concrete_eq::<A>(),
            self matches Self::Both(id,_,frame) ==> decode.requires((frame,)) && collision.requires((id,)),
        ensures match self {
            Self::Staged(id,record)=>out matches Ok(Input::Staged(k,r)) && k==id && r==record,
            Self::Prepared(id,frame)=>out matches Ok(Input::Prepared(k,f)) && k==id && f==frame,
            Self::Both(id,record,frame)=>match out {
                Ok(Input::Prepared(k,f))=>k==id && f==frame && decode.ensures((frame,),Ok(*record)),
                Ok(Input::Staged(_, _))=>false,
                Err(e)=>decode.ensures((frame,),Err(e)) || (collision.ensures((id,),e) &&
                    exists|other:A| other!=*record && #[trigger] decode.ensures((frame,),Ok(other))),
            },
        },
    {
        match self {
            Self::Staged(id,record)=>Ok(Input::Staged(id,record)),
            Self::Prepared(id,frame)=>Ok(Input::Prepared(id,frame)),
            Self::Both(id,record,frame)=>{
                let decoded=decode(frame)?;
                proof {reveal(vstd::laws_eq::obeys_concrete_eq);}
                if &decoded==record {Ok(Input::Prepared(id,frame))} else {Err(collision(id))}
            },
        }
    }
}

#[cfg(verus_keep_ghost)]
type Entries<'a,T> = Seq<(&'a ObjectId,&'a T)>;

spec fn rest<'a,T>(head:Option<(&'a ObjectId,&'a T)>,tail:Entries<'a,T>) -> Entries<'a,T> {
    match head {Some(h)=>seq![h]+tail,None=>tail}
}

pub(super) open spec fn enumerates<T>(rows:Entries<T>,table:Map<ObjectId,T>) -> bool {
    &&& rows.len()==table.len()
    &&& rows.unref().to_set()==table.kv_pairs()
    &&& increasing_seq(rows.map_values(|kv:(&ObjectId,&T)| *kv.0))
}

pub(super) open spec fn events<'a,A,B>(left:Entries<'a,A>,right:Entries<'a,B>) -> Seq<Row<'a,A,B>>
    decreases left.len()+right.len(),
{
    if left.len()==0 && right.len()==0 {Seq::empty()} else {
        let l=left.first(); let r=right.first();
        if right.len()==0 || (left.len()>0 && l.0.cmp_spec(r.0) is Less) {
            seq![Row::Staged(*l.0,l.1)]+events(left.drop_first(),right)
        } else if left.len()==0 || l.0.cmp_spec(r.0) is Greater {
            seq![Row::Prepared(*r.0,r.1)]+events(left,right.drop_first())
        } else {
            seq![Row::Both(*l.0,l.1,r.1)]+events(left.drop_first(),right.drop_first())
        }
    }
}

/// Project the emitted rows back onto both ordered inputs, preserving every identity and value.
pub(super) open spec fn covers<'a,A,B>(rows:Seq<Row<'a,A,B>>,left:Entries<'a,A>,right:Entries<'a,B>) -> bool
    decreases rows.len(),
{
    if rows.len()==0 {left.len()==0 && right.len()==0} else {
        match rows.first() {
            Row::Staged(k,v)=>left.len()>0 && k==*left.first().0 && v==left.first().1 &&
                covers(rows.drop_first(),left.drop_first(),right),
            Row::Prepared(k,v)=>right.len()>0 && k==*right.first().0 && v==right.first().1 &&
                covers(rows.drop_first(),left,right.drop_first()),
            Row::Both(k,v,f)=>left.len()>0 && right.len()>0 && k==*left.first().0 && k==*right.first().0 &&
                v==left.first().1 && f==right.first().1 && covers(rows.drop_first(),left.drop_first(),right.drop_first()),
        }
    }
}

proof fn complete_merge<'a,A,B>(left:Entries<'a,A>,right:Entries<'a,B>)
    requires obeys_cmp_concrete_eq::<ObjectId>(),
    ensures covers(events(left,right),left,right),
    decreases left.len()+right.len(),
{
    if left.len()==0 && right.len()==0 {return;}
    let rows=events(left,right);
    let order=left.first().0.cmp_spec(right.first().0);
    if right.len()==0 || (left.len()>0 && order is Less) {
        assert(rows.drop_first() =~= events(left.drop_first(),right));
        complete_merge(left.drop_first(),right);
    } else if left.len()==0 || order is Greater {
        assert(rows.drop_first() =~= events(left,right.drop_first()));
        complete_merge(left,right.drop_first());
    } else {
        assert(*left.first().0==*right.first().0);
        assert(rows.drop_first() =~= events(left.drop_first(),right.drop_first()));
        complete_merge(left.drop_first(),right.drop_first());
    }
}

pub(super) open spec fn written<'a,A,B,S,E,F:Fn(S,Row<'a,A,B>)->Result<S,E>>(
    write:F,start:S,rows:Seq<Row<'a,A,B>>,end:S) -> bool
    decreases rows.len(),
{
    if rows.len()==0 {start==end} else {
        exists|prev:S| written(write,start,rows.drop_last(),prev) && #[trigger] write.ensures((prev,rows.last()),Ok(end))
    }
}

pub(super) open spec fn outcome<'a,A,B,S,E,F:Fn(S,Row<'a,A,B>)->Result<S,E>>(
    write:F,start:S,rows:Seq<Row<'a,A,B>>,out:Result<S,E>) -> bool {
    match out {
        Ok(end)=>written(write,start,rows,end),
        Err(error)=>exists|n:int,prev:S| 0<=n<rows.len() && written(write,start,rows.take(n),prev) &&
            #[trigger] write.ensures((prev,rows[n]),Err(error)),
    }
}

pub(super) fn merge<'a,A,B,S,E,F:Fn(S,Row<'a,A,B>)->Result<S,E>>(
    staged:&'a BTreeMap<ObjectId,A>,prepared:&'a BTreeMap<ObjectId,B>,initial:S,write:F) -> (out:Result<S,E>)
    requires btree_map_inv(staged),btree_map_inv(prepared),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|s:S,row:Row<'a,A,B>| #[trigger] write.requires((s,row)),
    ensures exists|a:Entries<'a,A>,b:Entries<'a,B>| enumerates(a,staged@) && enumerates(b,prepared@) &&
        covers(events(a,b),a,b) && #[trigger] outcome(write,initial,events(a,b),out),
{
    let mut left=staged.iter();
    let mut right=prepared.iter();
    let ghost a=left.remaining();
    let ghost b=right.remaining();
    let ghost all=events(a,b);
    proof {complete_merge(a,b); }
    let mut l=left.next();
    let mut r=right.next();
    assert(rest(l,left.remaining()) =~= a);
    assert(rest(r,right.remaining()) =~= b);
    let ghost mut fuel=staged.len() as int+prepared.len() as int;
    let mut state=initial;
    let ghost mut done:Seq<Row<'a,A,B>>=Seq::empty();
    loop
        invariant
            enumerates(a,staged@),enumerates(b,prepared@),all==events(a,b),covers(all,a,b),obeys_cmp::<ObjectId>(),
            l.is_none() ==> left.remaining().len()==0,r.is_none() ==> right.remaining().len()==0,
            all==done+events(rest(l,left.remaining()),rest(r,right.remaining())),
            fuel==rest(l,left.remaining()).len()+rest(r,right.remaining()).len(),
            written(write,initial,done,state),
            forall|s:S,row:Row<'a,A,B>| #[trigger] write.requires((s,row)),
        decreases fuel,
    {
        let ghost ls=rest(l,left.remaining()); let ghost rs=rest(r,right.remaining());
        proof {reveal(vstd::laws_cmp::obeys_cmp_ord);}
        let row=match (l,r) {
            (Some((i,record)),Some((j,frame)))=>match i.cmp(j) {
                Ordering::Less=>Row::Staged(*i,record),
                Ordering::Greater=>Row::Prepared(*j,frame),
                Ordering::Equal=>Row::Both(*i,record,frame),
            },
            (Some((i,record)),None)=>Row::Staged(*i,record),
            (None,Some((j,frame)))=>Row::Prepared(*j,frame),
            (None,None)=>{
                assert(all =~= done);
                assert(outcome(write,initial,events(a,b),Ok(state)));
                return Ok(state);
            },
        };
        if !matches!(row,Row::Prepared(..)) {
            l=left.next();
            assert(rest(l,left.remaining()) =~= ls.drop_first());
        }
        if !matches!(row,Row::Staged(..)) {
            r=right.next();
            assert(rest(r,right.remaining()) =~= rs.drop_first());
        }
        assert(events(ls,rs) =~= seq![row]+events(rest(l,left.remaining()),rest(r,right.remaining())));
        let ghost prior=state;
        state=match write(state,row) {
            Ok(s)=>s,Err(e)=>{
                assert(all.take(done.len() as int) =~= done);
                assert(all[done.len() as int]==row);
                assert(outcome(write,initial,events(a,b),Err(e)));
                return Err(e);
            },
        };
        proof {
            fuel=fuel-(if row is Both {2int} else {1int});
            let previous=done;
            done=done.push(row);
            assert(done.drop_last() =~= previous && done.last()==row);
            assert(written(write,initial,done.drop_last(),prior));
            assert(written(write,initial,done,state));
            assert(all =~= done+events(rest(l,left.remaining()),rest(r,right.remaining())));
        };
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_sources_emit_one_matching_frame_and_stop_before_a_collision() {
        let id = |n| ObjectId::new([n; 32]);
        let staged = BTreeMap::from([(id(1), 11), (id(3), 33), (id(5), 55)]);
        let mut prepared = BTreeMap::from([(id(2), 22), (id(3), 33), (id(6), 66)]);
        let run = |frames: &BTreeMap<_, _>, emitted: &mut Vec<_>| {
            merge(&staged, frames, emitted, |out, row| {
                let input = row.resolve(|frame| Ok(*frame), |collision| collision)?;
                out.push(match input {
                    Input::Staged(k, v) => (k, *v, false),
                    Input::Prepared(k, v) => (k, *v, true),
                });
                Ok(out)
            })
            .map(drop)
        };
        let mut emitted = Vec::new();
        run(&prepared, &mut emitted).unwrap();
        assert_eq!(
            emitted,
            [
                (id(1), 11, false),
                (id(2), 22, true),
                (id(3), 33, true),
                (id(5), 55, false),
                (id(6), 66, true)
            ]
        );
        prepared.insert(id(3), 99);
        emitted.clear();
        assert_eq!(run(&prepared, &mut emitted), Err(id(3)));
        assert_eq!(emitted, [(id(1), 11, false), (id(2), 22, true)]);
    }
}
