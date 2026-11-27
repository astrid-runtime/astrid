//! Each state reference must have an owner before it can influence a header.
use crate::{header_components as c,ObjectReference,ObjectId,ReferenceKind,RootState};
use vstd::prelude::*;

verus! {
fn decode_one<P,C,E,F,Q>(owner:&P,root:RootState,refs:&[ObjectReference],catalog:F,charge:Q)
    -> (out:Result<c::Components<C>,c::Error<E>>)
    where F:Fn(&P,ObjectId,RootState)->Result<C,E>,Q:Fn(&P,c::Charge,&ObjectReference,RootState)->Result<u64,E>,
    requires refs.len()==1, forall|id:ObjectId| #[trigger] catalog.requires((owner,id,root)),
        forall|k:c::Charge,r:&ObjectReference| #[trigger] charge.requires((owner,k,r,root)),
    ensures ({
        let r = refs@[0];
        let (label,id,kind) = r.fields();
        let kv = label == b"kv"@;
        let ws = label.len() >= 10 && label.take(10) == b"workspace/"@;
        match out {
            Ok(p) => {
                &&& kind == ReferenceKind::Owns
                &&& if label == b"content"@ {
                    p.preserved.len()==0 && p.other_bytes==0 &&
                        (p.catalog matches Some(cat) && catalog.ensures((owner,id,root),Ok(cat)))
                } else {
                    p.catalog.is_none() && p.preserved.len()==1 && p.preserved@[0].fields()==r.fields() &&
                    if kv || ws {charge.ensures((owner,if kv {c::Charge::Kv} else {c::Charge::Workspace},&r,root),Ok(p.other_bytes))}
                    else {p.other_bytes==0}
                }
            },
            Err(c::Error::NotOwning) => kind != ReferenceKind::Owns,
            Err(c::Error::Overflow) => false,
            Err(c::Error::Storage(e)) => kind == ReferenceKind::Owns && if label == b"content"@ {
                catalog.ensures((owner,id,root),Err(e))
            } else {
                (kv || ws) && charge.ensures((owner,if kv {c::Charge::Kv} else {c::Charge::Workspace},&r,root),Err(e))
            },
        }
    }),
{
    let out = c::fold(owner,root,refs,catalog,charge);
    proof {
        let r = refs@[0];
        if let Ok(p) = &out {
            let obs = choose|obs:Seq<c::Observation<C>>| obs.len()==1 && p.other_bytes==#[trigger] c::total(obs) &&
                p.catalog==c::last_catalog(obs) && forall|j:int| 0<=j<obs.len() ==> c::accepted(owner,root,&refs@[j],#[trigger] obs[j],catalog,charge);
            assert(c::accepted(owner,root,&r,obs[0],catalog,charge));
            assert(obs.drop_last() =~= Seq::empty());
            reveal_with_fuel(c::total,2); reveal_with_fuel(c::last_catalog,2);
            let keep = |r:ObjectReference| r.fields().0 != b"content"@;
            assert(refs@.drop_last() =~= Seq::empty());
            assert(refs@.filter(keep) == if keep(r) {seq![r]} else {Seq::empty()}) by { reveal_with_fuel(Seq::filter,2); }
            let fields = |r:ObjectReference| r.fields();
            assert(p.preserved@.map_values(fields) == refs@.filter(keep).map_values(fields));
            assert(p.preserved@.map_values(fields).len() == p.preserved.len());
            assert(refs@.filter(keep).map_values(fields).len() == refs@.filter(keep).len());
            if keep(r) {assert(p.preserved@.map_values(fields)[0] == r.fields());}
            assert(c::total(obs) == match obs[0] { c::Observation::Bytes(n)=> n as nat, _=>0 });
            assert(c::last_catalog(obs) == match obs[0] { c::Observation::Catalog(cat)=>Some(cat), _=>None });
            if r.fields().0 == b"content"@ {
                assert(p.catalog matches Some(cat) && catalog.ensures((owner,r.fields().1,root),Ok(cat)));
            } else if r.fields().0 == b"kv"@ { assert(charge.ensures((owner,c::Charge::Kv,&r,root),Ok(p.other_bytes))); }
            else if c::workspace(r.fields().0) { assert(charge.ensures((owner,c::Charge::Workspace,&r,root),Ok(p.other_bytes))); }
        } else if let Err(e) = &out {
            let (obs,n) = choose|obs:Seq<c::Observation<C>>,n:u64| obs.len()<refs.len()
                && (forall|j:int| 0<=j<obs.len() ==> c::accepted(owner,root,&refs@[j],#[trigger] obs[j],catalog,charge))
                && #[trigger] c::failure(owner,root,&refs@[obs.len() as int],c::total(obs),n,*e,catalog,charge);
            assert(obs =~= Seq::empty());
            assert(c::total(obs)==0);
            assert(c::failure(owner,root,&r,0,n,*e,catalog,charge));
            assert(!(*e is Overflow));
        }
    }
    out
}
}
