//! Admission after enumerating the two durable token marker namespaces.
use crate::{marker_batch, marker_key, token_authority::{self, Admission, Marker}};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::string::StringSliceAdditionalSpecFns;
use vstd::{laws_eq::obeys_concrete_eq, std_specs::hash::{hash_map_inv, obeys_key_model}};

verus! {

type Id = [u8; 16];
type Key = Vec<u8>;

spec fn valid(key: Key) -> bool { exists|id:Id| #[trigger] marker_key::spells(id@,key@) }

spec fn listed(keys: Seq<Key>, id: Id) -> bool {
    exists|i:int| 0 <= i < keys.len() && #[trigger] marker_key::spells(id@,keys[i]@)
}

fn collect_namespace(
    groups: &mut HashMap<Id,Vec<Marker>>, keys: &[Key], kind: Marker,
)
    requires hash_map_inv(old(groups)), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        forall|i:int| 0 <= i < keys.len() ==> #[trigger] valid(keys@[i]),
    ensures hash_map_inv(final(groups)),
        forall|id:Id,tag:Marker| #[trigger] marker_batch::has(final(groups)@,id,tag) ==
            (marker_batch::has(old(groups)@,id,tag) || (tag == kind && listed(keys@,id))),
{
    let decode = |key: &Key| -> (out: Result<Id,()>)
        ensures forall|id:Id| #[trigger] marker_key::spells(id@,key@) ==> out == Ok(id),
            out matches Ok(id) ==> marker_key::spells(id@,key@),
            out.is_err() ==> !valid(*key),
    {
        let out = marker_key::decode_compatible(key, |_bytes: &[u8]| -> (result: Result<Id,()>)
            ensures result == Err(()),
        { Err(()) });
        proof {
            if out.is_err() && valid(*key) {
                let id = choose|id:Id| marker_key::spells(id@,key@);
                assert(out == Ok(id));
            }
            if let Ok(id) = out {
                if valid(*key) {
                    let original = choose|original:Id| marker_key::spells(original@,key@);
                    assert(out == Ok(original));
                }
            }
        }
        out
    };
    let result = marker_batch::group(groups,keys,kind,decode);
    let ghost ids = choose|ids: Seq<Id>| marker_batch::grouped(old(groups)@,groups@,ids,kind)
        && marker_batch::decoded(keys@,ids,decode) && match result {
            Ok(()) => ids.len() == keys.len(),
            Err(e) => ids.len() < keys.len() && decode.ensures((&keys@[ids.len() as int],),Err(e)),
        };
    if result.is_err() {
        let ghost n = ids.len() as int;
        assert(valid(keys@[n]));
        let ghost id = choose|id:Id| marker_key::spells(id@,keys@[n]@);
        assert(decode.ensures((&keys@[n],),Err(())));
        assert(marker_key::spells(id@,keys@[n]@));
        assert(false);
    }
    assert forall|id:Id| #[trigger] ids.contains(id) == listed(keys@,id) by {
        if ids.contains(id) {
            let i = choose|i:int| 0 <= i < ids.len() && ids[i] == id;
            assert(decode.ensures((&keys@[i],),Ok(ids[i])));
            assert(marker_key::spells(id@,keys@[i]@));
        }
        if listed(keys@,id) {
            let i = choose|i:int| 0 <= i < keys.len() && marker_key::spells(id@,keys@[i]@);
            assert(decode.ensures((&keys@[i],),Ok(ids[i])));
            assert(ids[i] == id);
        }
    }
}

/// Both namespaces replay into a single store. One token may be present in both.
fn reopen(revoked: &[Key], consumed: &[Key], target: Id, single_use: bool) -> (decision: Admission)
    requires obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        forall|i:int| 0 <= i < revoked.len() ==> #[trigger] valid(revoked@[i]),
        forall|i:int| 0 <= i < consumed.len() ==> #[trigger] valid(consumed@[i]),
    ensures (decision is Revoked) == listed(revoked@,target),
        (decision is AlreadyUsed) == (!listed(revoked@,target) && single_use && listed(consumed@,target)),
        (decision is Allowed) == (!listed(revoked@,target) && (!single_use || !listed(consumed@,target))),
{
    let mut recorded = HashMap::new();
    let kinds = Marker::recovery_order();
    let revoked_namespace = kinds[0].namespace();
    let consumed_namespace = kinds[1].namespace();
    assert(revoked_namespace@ == "caps:revoked"@ && consumed_namespace@ == "caps:used"@);
    assert(!marker_batch::has(recorded@,target,Marker::Revoked));
    assert(!marker_batch::has(recorded@,target,Marker::Consumed));
    collect_namespace(&mut recorded,revoked,kinds[0]);
    assert(marker_batch::has(recorded@,target,Marker::Revoked) == listed(revoked@,target));
    assert(!marker_batch::has(recorded@,target,Marker::Consumed));
    collect_namespace(&mut recorded,consumed,kinds[1]);
    assert(marker_batch::has(recorded@,target,Marker::Revoked) == listed(revoked@,target));
    assert(marker_batch::has(recorded@,target,Marker::Consumed) == listed(consumed@,target));
    let ghost history = if recorded@.contains_key(target) { recorded@[target]@ } else { Seq::empty() };
    proof { token_authority::replay_keeps_markers(history); }
    let live = token_authority::recover_authority(recorded);
    let decision = token_authority::status(&live,&target).admit(single_use);
    assert((decision is Revoked) == listed(revoked@,target));
    assert((decision is AlreadyUsed) == (!listed(revoked@,target) && single_use && listed(consumed@,target)));
    decision
}

type Presence = std::collections::BTreeMap<Vec<u8>,bool>;

/// Input to this boundary is the post-overlay presence table for one namespace.
spec fn canonical_namespace(table: &Presence, ns:Seq<u8>) -> bool {
    &&& forall|k:Vec<u8>| table@.get(k) == Some(true) ==> #[trigger] crate::encoding::matches_prefix(k@,ns + seq![0u8])
    &&& forall|suffix:Seq<u8>| #[trigger] table.deep_view().get(ns + seq![0u8] + suffix) == Some(true) ==>
        exists|id:Id| #[trigger] marker_key::spells(id@,suffix)
}

fn projected_markers(table:&Presence,ns:&[u8],target:&Id) -> (out:Vec<Key>)
    requires vstd::std_specs::btree::btree_map_inv(table),vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),
        vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),canonical_namespace(table,ns@),
    ensures forall|i:int| 0 <= i < out.len() ==> #[trigger] valid(out@[i]),
        forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==>
            listed(out@,*target) == (table.deep_view().get(ns@ + seq![0u8] + text) == Some(true)),
{
    let key = marker_key::encode(target);
    let rows = crate::hosted_key_projection::namespace_keys(table,ns,&key);
    assert forall|i:int| 0 <= i < rows.len() implies #[trigger] valid(rows@[i]) by {
        assert(table.deep_view().get(ns@ + seq![0u8] + rows@[i]@) == Some(true));
    }
    assert(listed(rows@,*target) == (exists|i:int| 0 <= i < rows.len() && #[trigger] rows@[i]@ == key@)) by {
        if listed(rows@,*target) {
            let i = choose|i:int| 0 <= i < rows.len() && marker_key::spells(target@,rows@[i]@);
            marker_key::unique_text(target@,rows@[i]@,key@);
        } else if exists|i:int| 0 <= i < rows.len() && #[trigger] rows@[i]@ == key@ {
            let i = choose|i:int| 0 <= i < rows.len() && rows@[i]@ == key@;
            assert(marker_key::spells(target@,rows@[i]@));
        }
    }
    assert forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) implies
        listed(rows@,*target) == (table.deep_view().get(ns@ + seq![0u8] + text) == Some(true)) by {
        marker_key::unique_text(target@,text,key@);
    }
    rows
}

/// First admission after enumerating canonical keys from both physical images.
fn admission_from_images(revoked:&Presence,consumed:&Presence,target:Id,single_use:bool) -> (out:Admission)
    requires vstd::std_specs::btree::btree_map_inv(revoked),vstd::std_specs::btree::btree_map_inv(consumed),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
        canonical_namespace(revoked,"caps:revoked".spec_bytes()),canonical_namespace(consumed,"caps:used".spec_bytes()),
    ensures forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==> ({
        let r = revoked.deep_view().get("caps:revoked".spec_bytes() + seq![0u8] + text) == Some(true);
        let c = consumed.deep_view().get("caps:used".spec_bytes() + seq![0u8] + text) == Some(true);
        &&& (out is Revoked) == r
        &&& (out is AlreadyUsed) == (!r && single_use && c)
        &&& (out is Allowed) == (!r && (!single_use || !c))
    }),
{
    let order = Marker::recovery_order();
    let revoked_keys = projected_markers(revoked,order[0].namespace().as_bytes(),&target);
    let consumed_keys = projected_markers(consumed,order[1].namespace().as_bytes(),&target);
    reopen(&revoked_keys,&consumed_keys,target,single_use)
}

/// If a canceled CAS installed its marker, the next attempt reads that entry
/// at the same physical address even when live completion never ran.
fn retry_after_unobserved_marker(live:&mut HashMap<Id,token_authority::TokenStatus>,target:Id,
    overlay:Option<&std::sync::Arc<crate::traversal::Node>>) -> (admitted:bool)
    requires hash_map_inv(old(live)),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
        vstd::pervasive::obeys_clone_eq::<Id>(),
        forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==>
            crate::traversal::lookup_spec(crate::traversal::deref_option(overlay),"caps:used".spec_bytes() + seq![0u8] + text)
                matches Some(Some(_)),
    ensures !admitted, final(live)@.contains_key(target) && final(live)@[target].used(),
        final(live)@ == old(live)@.insert(target,final(live)@[target]),
{
    use crate::kv_replacement::Replacement;
    let attempt = token_authority::Consumption::new(&target);
    let (ns,id) = attempt.address();
    assert(ns@ == "caps:used"@);
    let text = marker_key::encode(id);
    let address = crate::encoding::composite(ns.as_bytes(),&text);
    let read = |_:&(),key:&[u8]| -> (r:Result<Option<Vec<u8>>,()>)
        requires key@ == address@,
        ensures r matches Ok(Some(_)),
    {
        match crate::traversal::lookup(overlay,key) {
            Some(Some(bytes)) => Ok(Some(bytes.clone())),
            _ => { assert(false); Err(()) }
        }
    };
    let Ok((won,rows,changed)) = Replacement::compare_at(&(),&address,None,&[1],read) else {assert(false);return true;};
    assert(!won && rows.len() == 0 && !changed);
    let publish = |_:Vec<Replacement>| -> (out:Result<bool,()>) requires false, {Err(())};
    let Ok(Some(result)) = crate::mutation_ack::finish(won,rows,changed,publish) else {assert(false);return true;};
    attempt.finish(live,result)
}

/// A rejected second row returns its exact error after recording only the first.
/// This covers the error branch independently of the all-canonical assumption.
fn rejected_row(first: u64, error: u64, later: u64) {
    let mut recorded = HashMap::new();
    let keys: [Result<u64,u64>;3] = [Ok(first),Err(error),Ok(later)];
    let decode = |row: &Result<u64,u64>| -> (out: Result<u64,u64>)
        ensures out == *row,
    { *row };
    let result = marker_batch::group(&mut recorded,&keys,Marker::Revoked,decode);
    let ghost ids = choose|ids:Seq<u64>| marker_batch::grouped(Map::empty(),recorded@,ids,Marker::Revoked)
        && marker_batch::decoded(keys@,ids,decode) && match result {
            Ok(()) => ids.len() == keys.len(),
            Err(e) => ids.len() < keys.len() && decode.ensures((&keys@[ids.len() as int],),Err(e)),
        };
    proof { if ids.len() > 1 { assert(decode.ensures((&keys@[1],),Ok(ids[1]))); } }
    assert(ids.len() == 1);
    assert(decode.ensures((&keys@[0],),Ok(ids[0])));
    assert(result == Err(error));
    assert(recorded@.dom() =~= set![first]);
    assert(marker_batch::has(recorded@,first,Marker::Revoked));
}

}
