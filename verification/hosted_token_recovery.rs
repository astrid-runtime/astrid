//! Admission after enumerating the two durable token marker namespaces.
use crate::{checkpoint_range::Page, checkpoint_walk::Contents, hosted_checkpoint_walk as checkpoint, marker_batch, marker_key, token_authority::{self, Admission, Marker}};
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

fn recovered_admission(recorded:HashMap<Id,Vec<Marker>>,target:Id,single_use:bool) -> (out:Admission)
    requires hash_map_inv(&recorded),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
    ensures ({
        let revoked = marker_batch::has(recorded@,target,Marker::Revoked);
        let used = marker_batch::has(recorded@,target,Marker::Consumed);
        &&& (out is Revoked) == revoked
        &&& (out is AlreadyUsed) == (!revoked && used && single_use)
        &&& (out is Allowed) == (!revoked && (!used || !single_use))
    }),
{
    let ghost history = if recorded@.contains_key(target) { recorded@[target]@ } else { Seq::empty() };
    proof { token_authority::replay_keeps_markers(history); }
    let live = token_authority::recover_authority(recorded);
    token_authority::status(&live,&target).admit(single_use)
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
    recovered_admission(recorded,target,single_use)
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

/// A successful mixed enumeration cannot erase a canonical marker, even
/// when the legacy decoder supplies unrelated IDs or repeats an existing ID.
fn collect_mixed<E,F:Fn(&[u8])->Result<Id,E>+Copy>(groups:&mut HashMap<Id,Vec<Marker>>,
    rows:&[Key],kind:Marker,target:Id,legacy:F) -> (out:Result<(),E>)
    requires hash_map_inv(old(groups)),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
        forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures hash_map_inv(final(groups)),
        out.is_ok() ==> forall|m:Marker| marker_batch::has(old(groups)@,target,m) ||
            (kind == m && listed(rows@,target)) ==> #[trigger] marker_batch::has(final(groups)@,target,m),
        out matches Err(e) ==> exists|i:int,k:&[u8]| 0 <= i < rows.len() && #[trigger] rows@[i]@ == k@ &&
            #[trigger] legacy.ensures((k,),Err(e)),
{
    let decode = |key:&Key| -> (r:Result<Id,E>)
        ensures marker_key::spells(target@,key@) ==> r == Ok(target),
            r matches Err(e) ==> exists|k:&[u8]| k@ == key@ && #[trigger] legacy.ensures((k,),Err(e)),
    {
        let slice = key.as_slice();
        let fallback = |k:&[u8]| -> (v:Result<Id,E>) ensures legacy.ensures((k,),v), {legacy(k)};
        let result = marker_key::decode_compatible(slice,fallback);
        proof {
            if let Err(e) = &result {
                assert(!(exists|id:Id| #[trigger] marker_key::spells(id@,key@)));
                assert(fallback.ensures((slice,),Err(*e)));
            }
        }
        result
    };
    let result = marker_batch::group(groups,rows,kind,decode);
    let ghost ids = choose|ids:Seq<Id>| marker_batch::grouped(old(groups)@,groups@,ids,kind) &&
        marker_batch::decoded(rows@,ids,decode) && match result {
            Ok(()) => ids.len() == rows.len(),
            Err(e) => ids.len() < rows.len() && decode.ensures((&rows@[ids.len() as int],),Err(e)),
        };
    proof {
        if result.is_ok() {
            if listed(rows@,target) {
                let i = choose|i:int| 0 <= i < rows.len() && marker_key::spells(target@,rows@[i]@);
                assert(decode.ensures((&rows@[i],),Ok(ids[i])));
                assert(marker_key::spells(target@,rows@[i]@));
                assert(ids[i] == target);
                assert(ids.contains(target));
            }
        } else if let Err(e) = &result {
            let i = ids.len() as int;
            assert(decode.ensures((&rows@[i],),Err(*e)));
            let k = choose|k:&[u8]| k@ == rows@[i]@ && #[trigger] legacy.ensures((k,),Err(*e));
        }
    }
    result
}

spec fn failed_key<E,F:Fn(&[u8])->Result<Id,E>>(revoked:&Presence,consumed:&Presence,legacy:F,e:E,key:&[u8]) -> bool {
    legacy.ensures((key,),Err(e)) &&
        (revoked.deep_view().get("caps:revoked".spec_bytes() + seq![0u8] + key@) == Some(true) ||
         consumed.deep_view().get("caps:used".spec_bytes() + seq![0u8] + key@) == Some(true))
}

spec fn failed_image<E,F:Fn(&[u8])->Result<Id,E>>(revoked:&Presence,consumed:&Presence,legacy:F,e:E) -> bool {
    exists|key:&[u8]| #[trigger] failed_key(revoked,consumed,legacy,e,key)
}

/// A target with a canonical marker stays fenced in an image containing
/// arbitrary legacy keys. Any rejected row prevents startup from admitting.
fn mixed_image_fence<E,F:Fn(&[u8])->Result<Id,E>+Copy>(revoked:&Presence,consumed:&Presence,target:Id,single_use:bool,
    legacy:F) -> (out:Result<Admission,E>)
    requires vstd::std_specs::btree::btree_map_inv(revoked),vstd::std_specs::btree::btree_map_inv(consumed),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(), forall|k:&[u8]| #[trigger] legacy.requires((k,)),
        forall|k:Vec<u8>| revoked@.get(k) == Some(true) ==> #[trigger] crate::encoding::matches_prefix(k@,"caps:revoked".spec_bytes() + seq![0u8]),
        forall|k:Vec<u8>| consumed@.get(k) == Some(true) ==> #[trigger] crate::encoding::matches_prefix(k@,"caps:used".spec_bytes() + seq![0u8]),
    ensures out matches Ok(decision) ==> forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==> ({
        &&& revoked.deep_view().get("caps:revoked".spec_bytes() + seq![0u8] + text) == Some(true) ==> decision is Revoked
        &&& single_use && consumed.deep_view().get("caps:used".spec_bytes() + seq![0u8] + text) == Some(true) ==> !(decision is Allowed)
    }),
        match out { Err(e) => failed_image(revoked,consumed,legacy,e), _ => true },
{
    let key = marker_key::encode(&target);
    let kinds = Marker::recovery_order();
    let mut groups = HashMap::new();
    let r = crate::hosted_key_projection::namespace_keys(revoked,kinds[0].namespace().as_bytes(),&key);
    if let Err(e) = collect_mixed(&mut groups,&r,kinds[0],target,legacy) {
        proof {
            let (i,k) = choose|i:int,k:&[u8]| 0 <= i < r.len() && #[trigger] r@[i]@ == k@ && #[trigger] legacy.ensures((k,),Err(e));
            assert(revoked.deep_view().get("caps:revoked".spec_bytes() + seq![0u8] + r@[i]@) == Some(true));
            assert(legacy.ensures((k,),Err(e)));
            assert(revoked.deep_view().get("caps:revoked".spec_bytes() + seq![0u8] + k@) == Some(true));
            assert(failed_key(revoked,consumed,legacy,e,k));
            assert(failed_image(revoked,consumed,legacy,e));
        }
        return Err(e);
    }
    let c = crate::hosted_key_projection::namespace_keys(consumed,kinds[1].namespace().as_bytes(),&key);
    if let Err(e) = collect_mixed(&mut groups,&c,kinds[1],target,legacy) {
        proof {
            let (i,k) = choose|i:int,k:&[u8]| 0 <= i < c.len() && #[trigger] c@[i]@ == k@ && #[trigger] legacy.ensures((k,),Err(e));
            assert(consumed.deep_view().get("caps:used".spec_bytes() + seq![0u8] + c@[i]@) == Some(true));
            assert(legacy.ensures((k,),Err(e)));
            assert(consumed.deep_view().get("caps:used".spec_bytes() + seq![0u8] + k@) == Some(true));
            assert(failed_key(revoked,consumed,legacy,e,k));
            assert(failed_image(revoked,consumed,legacy,e));
        }
        return Err(e);
    }
    proof {
        if exists|i:int| 0 <= i < r.len() && #[trigger] r@[i]@ == key@ {
            let i = choose|i:int| 0 <= i < r.len() && r@[i]@ == key@;
            assert(marker_key::spells(target@,r@[i]@));
        }
        if exists|i:int| 0 <= i < c.len() && #[trigger] c@[i]@ == key@ {
            let i = choose|i:int| 0 <= i < c.len() && c@[i]@ == key@;
            assert(marker_key::spells(target@,c@[i]@));
        }
        assert forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) implies text == key@ by {
            marker_key::unique_text(target@,text,key@);
        }
    }
    Ok(recovered_admission(groups,target,single_use))
}

/// Point presence when the immutable overlay shadows the checkpoint. A
/// tombstone is an overlay observation and clears a checkpoint marker.
spec fn current_presence(table:Map<Seq<u8>,bool>,root:Option<std::sync::Arc<crate::traversal::Node>>,key:Seq<u8>) -> bool {
    match crate::traversal::lookup_spec(root,key) {
        Some(value) => value.is_some(),
        None => table.get(key) == Some(true),
    }
}

spec fn confined(table:&Presence,ns:Seq<u8>) -> bool {
    forall|k:Seq<u8>| table.deep_view().get(k) == Some(true) ==> #[trigger] crate::encoding::matches_prefix(k,ns + seq![0u8])
}

fn apply_marker_overlay(table:&mut Presence,root:Option<&std::sync::Arc<crate::traversal::Node>>,ns:&[u8])
    requires vstd::std_specs::btree::btree_map_inv(old(table)),vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),
        vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),crate::traversal::ordered(crate::traversal::deref_option(root)),
        confined(old(table),ns@),
    ensures vstd::std_specs::btree::btree_map_inv(final(table)),
        forall|k:Vec<u8>| final(table)@.get(k) == Some(true) ==> #[trigger] crate::encoding::matches_prefix(k@,ns@ + seq![0u8]),
        forall|suffix:Seq<u8>| (#[trigger] final(table).deep_view().get(ns@ + seq![0u8] + suffix) == Some(true)) ==
            current_presence(old(table).deep_view(),crate::traversal::deref_option(root),ns@ + seq![0u8] + suffix),
{
    let start = crate::encoding::composite(ns,&[]);
    let end = crate::encoding::prefix_end(ns,&[]);
    crate::hosted_overlay_range::apply_snapshot(root,&start,&end,table);
    assert forall|k:Vec<u8>| table@.get(k) == Some(true) implies #[trigger] crate::encoding::matches_prefix(k@,ns@ + seq![0u8]) by {
        crate::hosted_key_projection::visible(table,k@);
        assert(table.deep_view().get(k@) == Some(true));
        if !crate::encoding::matches_prefix(k@,start@) {
            assert(!crate::encoding::range_contains(start@,end@,k@));
            assert(old(table).deep_view().get(k@) == Some(true));
        }
    }
    assert forall|suffix:Seq<u8>| (#[trigger] table.deep_view().get(ns@ + seq![0u8] + suffix) == Some(true)) ==
        current_presence(old(table).deep_view(),crate::traversal::deref_option(root),ns@ + seq![0u8] + suffix) by {
        let k = start@ + suffix;
        assert(crate::encoding::matches_prefix(k,start@));
        assert(crate::encoding::range_contains(start@,end@,k));
    }
}

spec fn snapshot_refusal<E,F:Fn(&[u8])->Result<Id,E>>(revoked:Map<Seq<u8>,bool>,consumed:Map<Seq<u8>,bool>,
    rev_root:Option<std::sync::Arc<crate::traversal::Node>>,used_root:Option<std::sync::Arc<crate::traversal::Node>>,
    legacy:F,e:E) -> bool {
    exists|k:&[u8]| #[trigger] legacy.ensures((k,),Err(e)) &&
        (current_presence(revoked,rev_root,"caps:revoked".spec_bytes()+seq![0u8]+k@) ||
         current_presence(consumed,used_root,"caps:used".spec_bytes()+seq![0u8]+k@))
}

/// Each namespace can have its own captured header. State explicitly which
/// immutable checkpoint and overlay determine the initial admission.
fn reopen_with_overlays<E,F:Fn(&[u8])->Result<Id,E>+Copy>(revoked:Presence,consumed:Presence,
    rev_root:Option<&std::sync::Arc<crate::traversal::Node>>,used_root:Option<&std::sync::Arc<crate::traversal::Node>>,
    target:Id,single_use:bool,legacy:F) -> (out:Result<Admission,E>)
    requires vstd::std_specs::btree::btree_map_inv(&revoked),vstd::std_specs::btree::btree_map_inv(&consumed),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        crate::traversal::ordered(crate::traversal::deref_option(rev_root)),crate::traversal::ordered(crate::traversal::deref_option(used_root)),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
        confined(&revoked,"caps:revoked".spec_bytes()),confined(&consumed,"caps:used".spec_bytes()),
    ensures out matches Ok(decision) ==> forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==> ({
        &&& current_presence(revoked.deep_view(),crate::traversal::deref_option(rev_root),"caps:revoked".spec_bytes()+seq![0u8]+text) ==> decision is Revoked
        &&& single_use && current_presence(consumed.deep_view(),crate::traversal::deref_option(used_root),"caps:used".spec_bytes()+seq![0u8]+text) ==> !(decision is Allowed)
    }),
        match out { Err(e) => snapshot_refusal(revoked.deep_view(),consumed.deep_view(),crate::traversal::deref_option(rev_root),
            crate::traversal::deref_option(used_root),legacy,e), _ => true },
{
    let kinds = Marker::recovery_order();
    let rev_ns = kinds[0].namespace().as_bytes();
    let used_ns = kinds[1].namespace().as_bytes();
    assert(rev_ns@ == "caps:revoked".spec_bytes() && used_ns@ == "caps:used".spec_bytes());
    let ghost rev_before = revoked.deep_view();
    let ghost used_before = consumed.deep_view();
    let mut rev_image = revoked;
    let mut used_image = consumed;
    apply_marker_overlay(&mut rev_image,rev_root,rev_ns);
    apply_marker_overlay(&mut used_image,used_root,used_ns);
    let result = mixed_image_fence(&rev_image,&used_image,target,single_use,legacy);
    proof {
        if let Err(e) = &result {
            let k = choose|k:&[u8]| #[trigger] failed_key(&rev_image,&used_image,legacy,*e,k);
            assert(rev_image.deep_view().get("caps:revoked".spec_bytes()+seq![0u8]+k@) == Some(true) ||
                used_image.deep_view().get("caps:used".spec_bytes()+seq![0u8]+k@) == Some(true));
            assert(snapshot_refusal(rev_before,used_before,crate::traversal::deref_option(rev_root),
                crate::traversal::deref_option(used_root),legacy,*e));
        }
    }
    result
}

enum RecoveryError<E> {
    Page(Marker,E),
    Decoder(Marker,E),
}

spec fn marker_visible<I,T>(root:Option<I>,has:spec_fn(Page<I,T>)->bool,
    overlay:Option<std::sync::Arc<crate::traversal::Node>>,address:Seq<u8>) -> bool {
    match crate::traversal::lookup_spec(overlay,address) {
        Some(value) => value.is_some(),
        None => root matches Some(id) && has(Page::Root(id)),
    }
}

spec fn page_membership<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,
    has:spec_fn(Page<I,T>)->bool,ns:Seq<u8>,text:Seq<u8>) -> bool {
    checkpoint::image(read,has,ns+seq![0u8]+text,ns+seq![0u8],ns+seq![1u8])
}

spec fn ns_bytes(kind:Marker) -> Seq<u8> {
    match kind {Marker::Revoked => "caps:revoked".spec_bytes(), Marker::Consumed => "caps:used".spec_bytes()}
}

spec fn read_failed<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,e:E) -> bool {
    exists|p:Page<I,T>| #[trigger] read.ensures((p,),Err(e))
}

spec fn decoder_failed<E,F:Fn(&[u8])->Result<Id,E>>(legacy:F,e:E) -> bool {
    exists|k:&[u8]| #[trigger] legacy.ensures((k,),Err(e))
}

spec fn marker_in_snapshot<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(kind:Marker,target:Id,root:Option<I>,
    read:R,overlay:Option<std::sync::Arc<crate::traversal::Node>>) -> bool {
    exists|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) && ({
        let ns = ns_bytes(kind);
        let address = ns+seq![0u8]+text;
        ||| crate::traversal::lookup_spec(overlay,address) matches Some(Some(_))
        ||| exists|h:spec_fn(Page<I,T>)->bool| #[trigger] page_membership(read,h,ns,text) && marker_visible(root,h,overlay,address)
    })
}

fn restore_namespace<I,T,V,E,R,F>(groups:&mut HashMap<Id,Vec<Marker>>,kind:Marker,target:Id,root:Option<I>,read:R,
    overlay:Option<&std::sync::Arc<crate::traversal::Node>>,legacy:F) -> (out:Result<(),RecoveryError<E>>)
    where R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires checkpoint::readable(read),hash_map_inv(old(groups)),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        crate::traversal::ordered(crate::traversal::deref_option(overlay)),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures hash_map_inv(final(groups)), match out {
        Ok(()) => {
            &&& forall|m:Marker| marker_batch::has(old(groups)@,target,m) ==> #[trigger] marker_batch::has(final(groups)@,target,m)
            &&& marker_in_snapshot(kind,target,root,read,crate::traversal::deref_option(overlay)) ==> marker_batch::has(final(groups)@,target,kind)
        },
        Err(RecoveryError::Page(m,e)) => m == kind && read_failed(read,e),
        Err(RecoveryError::Decoder(m,e)) => m == kind && decoder_failed(legacy,e),
    },
{
    let ns = kind.namespace().as_bytes();
    assert(ns@ == ns_bytes(kind));
    let mut table = match checkpoint::scan(root,ns,read) {
        Ok(t) => t, Err(e) => return Err(RecoveryError::Page(kind,e)),
    };
    let ghost base = table.deep_view();
    let key = marker_key::encode(&target);
    apply_marker_overlay(&mut table,overlay,ns);
    let rows = crate::hosted_key_projection::namespace_keys(&table,ns,&key);
    if let Err(e) = collect_mixed(groups,&rows,kind,target,legacy) {
        proof {
            let (i,k) = choose|i:int,k:&[u8]| 0 <= i < rows.len() && #[trigger] rows@[i]@ == k@ && #[trigger] legacy.ensures((k,),Err(e));
            assert(decoder_failed(legacy,e));
        }
        return Err(RecoveryError::Decoder(kind,e));
    }
    proof {
        let tree = crate::traversal::deref_option(overlay);
        if marker_in_snapshot(kind,target,root,read,tree) {
            let text = choose|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) && ({
                let address = ns_bytes(kind)+seq![0u8]+text;
                ||| crate::traversal::lookup_spec(tree,address) matches Some(Some(_))
                ||| exists|h:spec_fn(Page<I,T>)->bool| #[trigger] page_membership(read,h,ns_bytes(kind),text) && marker_visible(root,h,tree,address)
            });
            marker_key::unique_text(target@,text,key@);
            let address = ns@+seq![0u8]+key@;
            if !(crate::traversal::lookup_spec(tree,address) matches Some(Some(_))) {
                let h = choose|h:spec_fn(Page<I,T>)->bool| #[trigger] page_membership(read,h,ns_bytes(kind),text) && marker_visible(root,h,tree,address);
                assert(checkpoint::image(read,h,address,ns@+seq![0u8],ns@+seq![1u8]));
                assert((base.get(address) == Some(true)) == (root matches Some(id) && h(Page::Root(id))));
            }
            assert(current_presence(base,crate::traversal::deref_option(overlay),address));
            assert(table.deep_view().get(address) == Some(true));
            let i = choose|i:int| 0 <= i < rows.len() && rows@[i]@ == key@;
            assert(marker_key::spells(target@,rows@[i]@));
            assert(listed(rows@,target));
        }
    }
    Ok(())
}

/// Run both namespace scans from their captured checkpoint root IDs. For each
/// target, the page model relates membership to the actual decoded leaves and
/// selected child pages. The captured overlays can mask either checkpoint.
fn reopen_from_pages<I,T,V,E,R,C,F>(rev_id:Option<I>,used_id:Option<I>,rev_read:R,used_read:C,
    rev_overlay:Option<&std::sync::Arc<crate::traversal::Node>>,used_overlay:Option<&std::sync::Arc<crate::traversal::Node>>,
    target:Id,single_use:bool,legacy:F) -> (out:Result<Admission,RecoveryError<E>>)
    where R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>, C:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,
        F:Fn(&[u8])->Result<Id,E>+Copy,
    requires checkpoint::readable(rev_read),checkpoint::readable(used_read),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        crate::traversal::ordered(crate::traversal::deref_option(rev_overlay)),crate::traversal::ordered(crate::traversal::deref_option(used_overlay)),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures match out {
        Ok(decision) => {
            &&& marker_in_snapshot(Marker::Revoked,target,rev_id,rev_read,crate::traversal::deref_option(rev_overlay)) ==> decision is Revoked
            &&& single_use && marker_in_snapshot(Marker::Consumed,target,used_id,used_read,crate::traversal::deref_option(used_overlay)) ==> !(decision is Allowed)
        },
        Err(RecoveryError::Page(Marker::Revoked,e)) => read_failed(rev_read,e),
        Err(RecoveryError::Page(Marker::Consumed,e)) => read_failed(used_read,e),
        Err(RecoveryError::Decoder(_,e)) => decoder_failed(legacy,e),
    },
{
    let kinds = Marker::recovery_order();
    let mut groups = HashMap::new();
    restore_namespace(&mut groups,kinds[0],target,rev_id,rev_read,rev_overlay,legacy)?;
    let ghost revoked = marker_batch::has(groups@,target,Marker::Revoked);
    restore_namespace(&mut groups,kinds[1],target,used_id,used_read,used_overlay,legacy)?;
    assert(revoked ==> marker_batch::has(groups@,target,Marker::Revoked));
    Ok(recovered_admission(groups,target,single_use))
}

/// Instantiate the page evidence for an actual decoded leaf and recover its
/// marker with the full walker, merger and store replay.
fn checkpoint_revocation(target:Id) -> (out:Result<Admission,RecoveryError<()>>)
    requires vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
    ensures out matches Ok(decision) && decision is Revoked,
{
    let ns = Marker::Revoked.namespace().as_bytes();
    let text = marker_key::encode(&target);
    let address = crate::encoding::composite(ns,&text);
    let end = crate::encoding::prefix_end(ns,&[]);
    let read = |_:Page<u64,()>| -> (r:Result<Contents<u64,(),()>,()>)
        ensures r matches Ok(Contents::Leaf(rows)) && rows.len() == 1 && rows@[0].key@ == address@,
    {
        let key = crate::encoding::composite(ns,&text);
        Ok(Contents::Leaf(vec![crate::checkpoint_leaf::Entry {key,value:()}]))
    };
    let empty = |_:Page<u64,()>| -> (r:Result<Contents<u64,(),()>,()>)
        ensures r matches Ok(Contents::Leaf(rows)) && rows.len() == 0, {Ok(Contents::Leaf(Vec::new()))};
    let legacy = |_:&[u8]| -> (r:Result<Id,()>) ensures r == Ok(target), {Ok(target)};
    proof {
        let h = |_:Page<u64,()>| true;
        let start = ns@ + seq![0u8];
        assert(crate::encoding::matches_prefix(address@,start));
        assert(crate::encoding::range_contains(start,end@,address@));
        assert forall|p:Page<u64,()>,rows:Vec<crate::checkpoint_leaf::Entry<()>>| #[trigger] read.ensures((p,),Ok(Contents::Leaf(rows))) implies
            checkpoint::contains(rows@,rows@.len(),address@,start,end@) by {
            assert(rows@[0].key@ == address@);
        }
        assert(page_membership(read,h,ns@,text@));
        assert(marker_visible(Some(1u64),h,None,address@));
        assert(marker_in_snapshot(Marker::Revoked,target,Some(1u64),read,None));
    }
    reopen_from_pages(Some(1u64),None,read,empty,None,None,target,true,legacy)
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
