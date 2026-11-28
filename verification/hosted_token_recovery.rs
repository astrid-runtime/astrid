//! Admission after enumerating the two durable token marker namespaces.
use crate::{checkpoint_range::Page, checkpoint_walk::Contents, hosted_checkpoint_walk as checkpoint, marker_batch, marker_key, token_authority::{self, Admission, Marker}};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::string::StringSliceAdditionalSpecFns;
use vstd::{laws_eq::obeys_concrete_eq, std_specs::hash::{hash_map_inv, obeys_key_model}};

#[path = "hosted_marker_append.rs"]
pub(crate) mod marker_append;

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

pub(crate) open spec fn ns_bytes(kind:Marker) -> Seq<u8> {
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

// Membership follows a finite chain of scheduled children to the actual marker
// row. A deletion in the captured overlay still takes precedence.
spec fn reachable_marker<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(kind:Marker,target:Id,
    root:Option<I>,read:R,overlay:Option<std::sync::Arc<crate::traversal::Node>>) -> bool {
    let ns = ns_bytes(kind);
    &&& crate::hosted_checkpoint_membership::stable(read)
    &&& exists|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) && ({
        let address = ns+seq![0u8]+text;
        let has = |p:Page<I,T>| crate::hosted_checkpoint_membership::reachable(read,p,address,ns+seq![0u8],ns+seq![1u8]);
        marker_visible(root,has,overlay,address)
    })
}

proof fn reachable_marker_in_snapshot<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(kind:Marker,target:Id,
    root:Option<I>,read:R,overlay:Option<std::sync::Arc<crate::traversal::Node>>)
    requires reachable_marker(kind,target,root,read,overlay),
    ensures marker_in_snapshot(kind,target,root,read,overlay),
{
    let ns = ns_bytes(kind);
    let text = choose|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) && ({
        let address = ns+seq![0u8]+text;
        let has = |p:Page<I,T>| crate::hosted_checkpoint_membership::reachable(read,p,address,ns+seq![0u8],ns+seq![1u8]);
        marker_visible(root,has,overlay,address)
    });
    let address = ns+seq![0u8]+text;
    let has = |p:Page<I,T>| crate::hosted_checkpoint_membership::reachable(read,p,address,ns+seq![0u8],ns+seq![1u8]);
    crate::hosted_checkpoint_membership::derive(read,address,ns+seq![0u8],ns+seq![1u8]);
    assert(page_membership(read,has,ns,text));
    assert(exists|h:spec_fn(Page<I,T>)->bool| #[trigger] page_membership(read,h,ns,text) && marker_visible(root,h,overlay,address));
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
            &&& reachable_marker(Marker::Revoked,target,rev_id,rev_read,crate::traversal::deref_option(rev_overlay)) ==> decision is Revoked
            &&& single_use && reachable_marker(Marker::Consumed,target,used_id,used_read,crate::traversal::deref_option(used_overlay)) ==> !(decision is Allowed)
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
    proof {
        let ro = crate::traversal::deref_option(rev_overlay);
        let uo = crate::traversal::deref_option(used_overlay);
        if reachable_marker(Marker::Revoked,target,rev_id,rev_read,ro) {
            reachable_marker_in_snapshot(Marker::Revoked,target,rev_id,rev_read,ro);
        }
        if reachable_marker(Marker::Consumed,target,used_id,used_read,uo) {
            reachable_marker_in_snapshot(Marker::Consumed,target,used_id,used_read,uo);
        }
    }
    let ghost revoked = marker_batch::has(groups@,target,Marker::Revoked);
    restore_namespace(&mut groups,kinds[1],target,used_id,used_read,used_overlay,legacy)?;
    assert(revoked ==> marker_batch::has(groups@,target,Marker::Revoked));
    Ok(recovered_admission(groups,target,single_use))
}

// Run both real namespace scans on the projection roots and overlays. The
// selected projection comes from cold replay of the owner-addressed component.
fn reopen_after_delta<P,B,V,T,W,E,L,M,R,C,F>(kind:Marker,target:Id,single_use:bool,
    revoked:&(crate::memo_projection::Projection<B>,V),consumed:&(crate::memo_projection::Projection<B>,V),
    rev_read:R,used_read:C,legacy:F,Ghost(owner):Ghost<P>,head:crate::ObjectId,Ghost(load):Ghost<L>,
    Ghost(measure):Ghost<M>,Ghost(text):Ghost<Seq<u8>>,Ghost(path):Ghost<Seq<crate::ObjectId>>) -> (out:Result<Admission,RecoveryError<E>>)
    where L:Fn(&P,crate::ObjectId)->Result<crate::delta_chain::Head,E>,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires checkpoint::readable(rev_read),checkpoint::readable(used_read),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
        marker_key::spells(target@,text),
        crate::projection_recovery::retained(&owner,head,path,load,ns_bytes(kind)+seq![0u8]+text,true),
        crate::projection_recovery::recovered(&owner,head,load,measure,if kind is Revoked {*revoked} else {*consumed}),
        if kind is Revoked {consumed.0.overlay.ordered_snapshot()} else {revoked.0.overlay.ordered_snapshot()},
    ensures match out {
        Ok(a) => (kind is Revoked ==> a is Revoked) && (single_use ==> !(a is Allowed)),
        Err(RecoveryError::Page(Marker::Revoked,e)) => read_failed(rev_read,e),
        Err(RecoveryError::Page(Marker::Consumed,e)) => read_failed(used_read,e),
        Err(RecoveryError::Decoder(_,e)) => decoder_failed(legacy,e),
    },
{
    proof {
        let pair=if kind is Revoked {*revoked} else {*consumed};
        let address=ns_bytes(kind)+seq![0u8]+text;
        crate::projection_recovery::retained_write(&owner,head,load,measure,pair,path,address,true);
        assert(crate::traversal::lookup_spec(pair.0.overlay.root,address) matches Some(Some(_)));
        if kind is Revoked {
            assert(marker_in_snapshot(kind,target,revoked.0.tree,rev_read,revoked.0.overlay.root));
        } else {
            assert(marker_in_snapshot(kind,target,consumed.0.tree,used_read,consumed.0.overlay.root));
        }
    }
    reopen_from_pages(revoked.0.tree,consumed.0.tree,rev_read,used_read,
        revoked.0.overlay.root.as_ref(),consumed.0.overlay.root.as_ref(),target,single_use,legacy)
}

enum ReopenError<E> { Projection(crate::projection_recovery::Error<E>), Namespace(RecoveryError<E>) }

// On a cache miss, connect the production decoder's *returned* projection to
// the two namespace scans. Reconstruction failure stops here before admission.
fn decode_then_reopen<'a,P,S,B,V,T,W,E,L,M,I,K,D,A,R,C,F>(owner:&'a P,head:crate::ObjectId,kind:Marker,
    target:Id,single_use:bool,other:&(crate::memo_projection::Projection<B>,V),load:L,measure:M,start:I,
    values:(K,D),translate:A,rev_read:R,used_read:C,legacy:F,Ghost(text):Ghost<Seq<u8>>,Ghost(path):Ghost<Seq<crate::ObjectId>>)
    -> (out:Result<Admission,ReopenError<E>>)
    where L:Fn(&P,crate::ObjectId)->Result<crate::delta_chain::Head,E>,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,I:FnOnce(&'a P)->S,
        K:Fn(S,Option<crate::ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        D:Fn(S,&crate::checkpoint_value::ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(crate::ObjectId,crate::delta_totals::ApplyError<E>)->E,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|p:&P,id:crate::ObjectId| #[trigger] load.requires((p,id)),
        forall|tree:Option<crate::ObjectId>| #[trigger] measure.requires((owner,tree)),start.requires((owner,)),
        forall|s:S,t:Option<crate::ObjectId>,key:&Vec<u8>| #[trigger] values.0.requires((s,t,key)),
        forall|s:S,v:&crate::checkpoint_value::ValueSlot| #[trigger] values.1.requires((s,v)),
        forall|id:crate::ObjectId,e:crate::delta_totals::ApplyError<E>| #[trigger] translate.requires((id,e)),
        checkpoint::readable(rev_read),checkpoint::readable(used_read),other.0.overlay.ordered_snapshot(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
        marker_key::spells(target@,text),
        crate::projection_recovery::retained(owner,head,path,load,ns_bytes(kind)+seq![0u8]+text,true),
    ensures out matches Ok(a) ==> (kind is Revoked ==> a is Revoked) && (single_use ==> !(a is Allowed)),
{
    let ghost reader = load;
    let ghost measured = measure;
    let selected=match crate::projection_recovery::read(owner,head,load,measure,start,values,translate) {
        Ok(p)=>p,Err(e)=>return Err(ReopenError::Projection(e)),
    };
    let (revoked,consumed)=match kind {Marker::Revoked=>(&selected,other),Marker::Consumed=>(other,&selected)};
    match reopen_after_delta::<P,B,V,T,W,E,L,M,R,C,F>(kind,target,single_use,revoked,consumed,rev_read,used_read,legacy,
        Ghost(*owner),head,Ghost(reader),Ghost(measured),Ghost(text),Ghost(path)) {
        Ok(a)=>Ok(a),Err(e)=>Err(ReopenError::Namespace(e)),
    }
}

enum CapturedError<E> { Graph(crate::header_graph::KvError<E>), Reopen(ReopenError<E>) }

// A cold header and the canonical marker load must use the physical component row of this owner.
fn reopen_captured_root<'a,P,S,B,V,T,W,E,L,M,I,K,D,A,R,C,F,G>(owner:&'a P,head:crate::ObjectId,kind:Marker,
    target:Id,single_use:bool,other:&(crate::memo_projection::Projection<B>,V),load:L,measure:M,start:I,
    values:(K,D),translate:A,rev_read:R,used_read:C,legacy:F,Ghost(text):Ghost<Seq<u8>>,Ghost(path):Ghost<Seq<crate::ObjectId>>,
    root:crate::RootState,v:crate::ObjectFormatVersion,graph_load:G,commit:std::sync::Arc<crate::ObjectRecord>,
    state_id:crate::ObjectId,state:std::sync::Arc<crate::ObjectRecord>,
    table:Ghost<spec_fn(P,crate::ObjectId)->Result<std::sync::Arc<crate::ObjectRecord>,E>>,
    Ghost(ci):Ghost<int>,Ghost(si):Ghost<int>)
    -> (out:Result<Option<Admission>,CapturedError<E>>)
    where L:Fn(&P,crate::ObjectId)->Result<crate::delta_chain::Head,E>,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,I:FnOnce(&'a P)->S,
        K:Fn(S,Option<crate::ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        D:Fn(S,&crate::checkpoint_value::ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(crate::ObjectId,crate::delta_totals::ApplyError<E>)->E,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
        G:Fn(&P,crate::ObjectId)->Result<std::sync::Arc<crate::ObjectRecord>,E>,
    requires forall|id:crate::ObjectId| #[trigger] graph_load.requires((owner,id)),
        forall|id:crate::ObjectId,x:Result<std::sync::Arc<crate::ObjectRecord>,E>|
            #[trigger] graph_load.ensures((owner,id),x) ==> x==(table@)(*owner,id),
        (table@)(*owner,root.commit)==Ok(commit), (table@)(*owner,state_id)==Ok(state),
        crate::header_graph::structural(*commit,crate::ObjectKind::Commit,v),
        crate::header_graph::structural(*state,crate::ObjectKind::PrincipalState,v),
        crate::ObjectRecord::labels_ordered(commit.contents().3),crate::ObjectRecord::labels_ordered(state.contents().3),
        0<=ci<commit.contents().3.len(),commit.contents().3[ci].fields()==(b"state"@,state_id,crate::ReferenceKind::Owns),
        0<=si<state.contents().3.len(),state.contents().3[si].fields()==(b"kv"@,head,crate::ReferenceKind::Owns),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|p:&P,id:crate::ObjectId| #[trigger] load.requires((p,id)),
        forall|tree:Option<crate::ObjectId>| #[trigger] measure.requires((owner,tree)),start.requires((owner,)),
        forall|s:S,t:Option<crate::ObjectId>,key:&Vec<u8>| #[trigger] values.0.requires((s,t,key)),
        forall|s:S,v:&crate::checkpoint_value::ValueSlot| #[trigger] values.1.requires((s,v)),
        forall|id:crate::ObjectId,e:crate::delta_totals::ApplyError<E>| #[trigger] translate.requires((id,e)),
        checkpoint::readable(rev_read),checkpoint::readable(used_read),other.0.overlay.ordered_snapshot(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
        marker_key::spells(target@,text),
        crate::projection_recovery::retained(owner,head,path,load,ns_bytes(kind)+seq![0u8]+text,true),
    ensures out matches Ok(found) ==> (found matches Some(a) &&
            (kind is Revoked ==> a is Revoked) && (single_use ==> !(a is Allowed))),
        out matches Err(e) ==> e is Reopen,
{
    let graph=|p:&P,r:crate::RootState| -> (q:Result<(crate::header_graph::Graph,Option<crate::ObjectId>),CapturedError<E>>)
        requires *p==*owner && r==root,
        ensures q matches Ok((g,Some(id))) && id==head && g.commit==commit && g.state_id==state_id && g.state==state,
    {
        match crate::hosted_workspace_references::kv_from_canonical_rows(p,r,v,commit,state_id,state,head,graph_load,table,Ghost(ci),Ghost(si)) {
            Ok(pair)=>Ok(pair),Err(e)=>Err(CapturedError::Graph(e)),
        }
    };
    let resolve=|p:&P,id:crate::ObjectId| -> (q:Result<Option<Admission>,CapturedError<E>>)
        requires *p==*owner && id==head,
        ensures q matches Ok(found) ==> (found matches Some(a) && (kind is Revoked ==> a is Revoked) && (single_use ==> !(a is Allowed))),
            q matches Err(e) ==> e is Reopen,
    {
        match decode_then_reopen(owner,id,kind,target,single_use,other,load,measure,start,values,translate,
            rev_read,used_read,legacy,Ghost(text),Ghost(path)) {
            Ok(a)=>Ok(Some(a)),Err(e)=>Err(CapturedError::Reopen(e)),
        }
    };
    match crate::memo_projection::read_root(owner,root,graph,||None,resolve) {
        Ok((_,decision))=>Ok(decision),Err(e)=>Err(e),
    }
}

/// Derive the marker write from the canonical component bytes recovered for
/// this owner. Every predecessor read uses the same validated object table.
fn reopen_loaded_marker<'a,P:Ord+Copy,S,B,V,T,W,E,KE,Check,Select,Fail,M,I,K,D,A,R,C,F>(
    graph:&'a crate::hosted_recovered_header::RecoveredGraph<P>,path:Ghost<Seq<crate::ObjectId>>,version:crate::ObjectFormatVersion,
    image:Ghost<Seq<u8>>,index:Ghost<Map<crate::ObjectId,crate::ArenaLocation>>,scheme:crate::root_wire::Scheme,
    kind:Marker,target:Id,single_use:bool,other:&(crate::memo_projection::Projection<B>,V),
    select:Select,fail:Fail,measure:M,start:I,values:(K,D),translate:A,rev_read:R,used_read:C,legacy:F)
    -> (out:Result<Admission,ReopenError<E>>)
    where Check:Fn(&[u8])->Option<KE>+Copy,Select:Fn(crate::ObjectId)->Check,Fail:Fn(crate::ObjectId)->E,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,I:FnOnce(&'a P)->S,
        K:Fn(S,Option<crate::ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        D:Fn(S,&crate::checkpoint_value::ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(crate::ObjectId,crate::delta_totals::ApplyError<E>)->E,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires vstd::laws_cmp::obeys_cmp::<P>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<P>(),
        graph.from_arena(image@,index@,scheme,version),graph.component.is_some(),
        path@.len()>0 && path@[0]==graph.component.unwrap(),
        forall|i:int| 0<=i<path@.len() ==> graph.records@.contains_key(#[trigger] path@[i]),
        forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==> crate::hosted_delta_mutation::marker_bytes(
            crate::hosted_journal_history::component_bytes(image@,index@[path@.last()]),ns_bytes(kind)+seq![0u8]+text),
        forall|i:int,text:Seq<u8>| 0<=i<path@.len()-1 && #[trigger] marker_key::spells(target@,text) ==>
            crate::hosted_delta_mutation::untouched_link(&graph.records@[#[trigger] path@[i]],path@[i+1],ns_bytes(kind)+seq![0u8]+text),
        forall|id:crate::ObjectId| #[trigger] select.requires((id,)),
        forall|id:crate::ObjectId| #[trigger] fail.requires((id,)),
        forall|id:crate::ObjectId,check:Check,b:&[u8]| #[trigger] select.ensures((id,),check) ==> #[trigger] check.requires((b,)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|tree:Option<crate::ObjectId>| #[trigger] measure.requires((&graph.owner,tree)),start.requires((&graph.owner,)),
        forall|s:S,t:Option<crate::ObjectId>,key:&Vec<u8>| #[trigger] values.0.requires((s,t,key)),
        forall|s:S,v:&crate::checkpoint_value::ValueSlot| #[trigger] values.1.requires((s,v)),
        forall|id:crate::ObjectId,e:crate::delta_totals::ApplyError<E>| #[trigger] translate.requires((id,e)),
        checkpoint::readable(rev_read),checkpoint::readable(used_read),other.0.overlay.ordered_snapshot(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures out matches Ok(decision) ==> (kind is Revoked ==> decision is Revoked) && (single_use ==> !(decision is Allowed)),
{
    let head=graph.component.unwrap();
    assert(path@[path@.len()-1]==path@.last());
    let ghost writer=path@.last();
    let text=marker_key::encode(&target);
    let address=Ghost(ns_bytes(kind)+seq![0u8]+text@);
    proof {
        crate::hosted_journal_history::component_contents(image@,(writer,index@[writer]),scheme,graph.records@[writer]);
        assert(crate::hosted_delta_mutation::marker_bytes(graph.records@[writer].contents().2,address@));
    }
    let owner=graph.owner;
    let load=|p:&P,id:crate::ObjectId| -> (out:Result<crate::delta_chain::Head,E>)
        ensures out matches Ok(h) ==> *p==owner && graph.records@.contains_key(id) && (id==writer ==>
            (h matches crate::delta_chain::Head::Delta{mutations,..} &&
            crate::overlay_batch::after_rows(mutations@,mutations.len() as nat,address@,None)==Some(true))) &&
            (forall|i:int| 0<=i<path@.len()-1 && id==#[trigger] path@[i] ==> (h matches crate::delta_chain::Head::Delta{previous,mutations,..} &&
                previous==Some(path@[i+1]) && crate::overlay_batch::after_rows(mutations@,mutations.len() as nat,address@,None).is_none())),
    {
        proof {reveal(vstd::laws_cmp::obeys_cmp_ord);reveal(vstd::laws_cmp::obeys_partial_cmp_spec_properties);}
        if !matches!(P::cmp(p,&owner),std::cmp::Ordering::Equal) {return Err(fail(id));}
        assert(*p==owner);
        let Some(record)=graph.records.get(&id) else {return Err(fail(id))};
        let check=select(id);
        let label=crate::projection_record::ROOT_LABEL.as_slice();
        match crate::projection_record::decode(record,version,label,check) {
            Ok(h)=>{
                proof {if id==writer {crate::hosted_delta_mutation::decoded_marker(record,address@,version,label,check,h);}
                    assert forall|i:int| 0<=i<path@.len()-1 && id==#[trigger] path@[i] implies
                        h matches crate::delta_chain::Head::Delta{previous,mutations,..} && previous==Some(path@[i+1]) &&
                        crate::overlay_batch::after_rows(mutations@,mutations.len() as nat,address@,None).is_none() by {
                        crate::hosted_delta_mutation::decoded_link(record,path@[i+1],address@,version,label,check,h);
                    }
                }
                Ok(h)
            },
            Err(_)=>Err(fail(id)),
        }
    };

    assert(crate::projection_recovery::retained(&graph.owner,head,path@,load,address@,true));
    decode_then_reopen(&graph.owner,head,kind,target,single_use,other,load,measure,start,values,translate,
        rev_read,used_read,legacy,Ghost(text@),path)
}

/// Follow the owner in a physically retained restart table to its marker and run admission.
/// A missing owner, unreadable header or different component yields no decision.
fn decide_recovered_marker<P:Ord+Copy,S,B,V,T,W,E,KE,Check,Select,Fail,M,I,K,D,A,R,C,F>(
    loaded:crate::hosted_recovered_roots::Loaded<P>,owner:P,newest:crate::ObjectId,path:Ghost<Seq<crate::ObjectId>>,version:crate::ObjectFormatVersion,
    image:Ghost<Seq<u8>>,index:Ghost<Map<crate::ObjectId,crate::ArenaLocation>>,scheme:crate::root_wire::Scheme,
    kind:Marker,target:Id,single_use:bool,other:&(crate::memo_projection::Projection<B>,V),
    select:Select,fail:Fail,measure:M,start:I,values:(K,D),translate:A,rev_read:R,used_read:C,legacy:F)
    -> (out:Option<(crate::RootState,Result<Admission,ReopenError<E>>)>)
    where Check:Fn(&[u8])->Option<KE>+Copy,Select:Fn(crate::ObjectId)->Check,Fail:Fn(crate::ObjectId)->E,
        M:FnOnce(&P,Option<crate::ObjectId>)->Result<crate::projection_recovery::Measured<B,V>,E>,I:FnOnce(&P)->S,
        K:Fn(S,Option<crate::ObjectId>,&Vec<u8>)->Result<(S,Option<Vec<u8>>),E>+Copy,
        D:Fn(S,&crate::checkpoint_value::ValueSlot)->Result<(S,Vec<u8>),E>+Copy,A:Fn(crate::ObjectId,crate::delta_totals::ApplyError<E>)->E,
        R:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,
        C:Fn(Page<crate::ObjectId,T>)->Result<Contents<crate::ObjectId,T,W>,E>,F:Fn(&[u8])->Result<Id,E>+Copy,
    requires vstd::laws_cmp::obeys_cmp::<P>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<P>(),
        crate::hosted_recovered_roots::retained(&loaded,image@,index@,scheme),path@.len()>0 && path@[0]==newest && loaded.records@.contains_key(path@.last()),
        forall|text:Seq<u8>| #[trigger] marker_key::spells(target@,text) ==> crate::hosted_delta_mutation::marker_bytes(
            crate::hosted_journal_history::component_bytes(image@,index@[path@.last()]),ns_bytes(kind)+seq![0u8]+text),
        forall|i:int| 0<=i<path@.len() ==> loaded.records@.contains_key(#[trigger] path@[i]),
        forall|i:int,text:Seq<u8>| 0<=i<path@.len()-1 && #[trigger] marker_key::spells(target@,text) ==>
            crate::hosted_delta_mutation::untouched_link(&loaded.records@[#[trigger] path@[i]],path@[i+1],ns_bytes(kind)+seq![0u8]+text),
        forall|id:crate::ObjectId| #[trigger] select.requires((id,)),
        forall|id:crate::ObjectId| #[trigger] fail.requires((id,)),
        forall|id:crate::ObjectId,check:Check,b:&[u8]| #[trigger] select.ensures((id,),check) ==> #[trigger] check.requires((b,)),
        vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|p:&P,tree:Option<crate::ObjectId>| *p==owner ==> #[trigger] measure.requires((p,tree)),
        forall|p:&P| *p==owner ==> #[trigger] start.requires((p,)),
        forall|s:S,t:Option<crate::ObjectId>,key:&Vec<u8>| #[trigger] values.0.requires((s,t,key)),
        forall|s:S,v:&crate::checkpoint_value::ValueSlot| #[trigger] values.1.requires((s,v)),
        forall|id:crate::ObjectId,e:crate::delta_totals::ApplyError<E>| #[trigger] translate.requires((id,e)),
        checkpoint::readable(rev_read),checkpoint::readable(used_read),other.0.overlay.ordered_snapshot(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),forall|k:&[u8]| #[trigger] legacy.requires((k,)),
    ensures out matches Some((root,result)) ==> loaded.history@.contains_key(owner) && root==loaded.history@[owner].0 &&
        loaded.records@.contains_key(newest) && (result matches Ok(decision) ==>
            (kind is Revoked ==> decision is Revoked) && (single_use ==> !(decision is Allowed))),
{
    let graph=crate::hosted_recovered_header::loaded_header(loaded,&owner,version,image,index,scheme)?;
    let component=graph.component?;
    if !component.same(&newest) {return None;}
    let result=reopen_loaded_marker(&graph,path,version,image,index,scheme,kind,target,single_use,other,
        select,fail,measure,start,values,translate,rev_read,used_read,legacy);
    Some((graph.root,result))
}

// A canonical marker delta followed by a physical delta for an unrelated key.
fn two_written_components(owner:u64,newest:crate::ObjectId,writer:crate::ObjectId,target:Id,kind:Marker)
    -> (out:Result<Admission,ReopenError<()>>)
    requires newest!=writer,vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
    ensures out matches Ok(a) ==> !(a is Allowed) && (kind is Revoked ==> a is Revoked),
{
    use crate::{delta_chain::Head,checkpoint_totals::NodeTotals,projection_recovery::Measured};
    let ns=kind.namespace().as_bytes();
    let text=marker_key::encode(&target);
    let address=crate::encoding::composite(ns,&text);
    proof {
        reveal_strlit("caps:used");reveal_strlit("caps:revoked");
        vstd::string::is_ascii_spec_bytes("caps:used");vstd::string::is_ascii_spec_bytes("caps:revoked");
        assert(ns@==ns_bytes(kind));
    }
    assert(36<=address.len()<=64 && ns.len()<=16);
    let n=(address.len() as u64).saturating_add(1);
    let m=n.saturating_add(4);
    let first=NodeTotals{entries:1,logical_bytes:1,quota_bytes:n};
    let last=NodeTotals{entries:2,logical_bytes:2,quota_bytes:m};
    let load=|p:&u64,id:crate::ObjectId| -> (out:Result<Head,()>)
        requires newest!=writer && ns.len()<=16 && n<=65 && address@==ns@+seq![0u8]+text@,
        ensures if *p==owner && (id==writer || id==newest) {
            out matches Ok(Head::Delta{previous,mutations,..}) && mutations.len()==1 &&
                (if id==writer {previous.is_none() && mutations@[0].key@==address@} else {
                    previous==Some(writer) && mutations@[0].key@==seq![120u8,0u8,121u8]}) && mutations@[0].value.is_some()
        } else {out.is_err()},
    {
        if *p!=owner {return Err(());}
        if id.same(&writer) {
            Ok(crate::hosted_delta_mutation::written_marker(crate::encoding::composite(ns,&text),None,0,0,first).1)
        } else if id.same(&newest) {
            Ok(crate::hosted_delta_mutation::written_marker(vec![120u8,0,121],Some(writer),1,n,last).1)
        } else {Err(())}
    };
    let zero=NodeTotals{entries:0,logical_bytes:0,quota_bytes:0};
    let measure=|_:&u64,tree:Option<crate::ObjectId>| -> (r:Result<Measured<(),()>,()>)
    {Ok(Measured{root:tree,totals:zero,boundary:(),validation:()})};
    let lookup=|_:(),_:Option<crate::ObjectId>,_:&Vec<u8>| -> (r:Result<((),Option<Vec<u8>>),()>) {Ok(((),None))};
    let value=|_:(),_:&crate::checkpoint_value::ValueSlot| -> (r:Result<((),Vec<u8>),()>) {Ok(((),vec![1u8]))};
    let page=|_:Page<crate::ObjectId,()>| -> (r:Result<Contents<crate::ObjectId,(),()>,()>) ensures r.is_err(), {Err(())};
    let legacy=|_:&[u8]| -> (r:Result<Id,()>) {Err(())};
    let other=(crate::memo_projection::Projection{head:None,tree:None,overlay:crate::overlay::OverlayMap::empty(),
        depth:0,delta_bytes:0,totals:zero,boundary:Some(())},());
    let ghost path=seq![newest,writer];
    proof {
        assert(ns@==ns_bytes(kind));
        assert(path.last()==writer);
        assert(crate::projection_recovery::head_writes(&owner,writer,load,address@,true));
        assert forall|i:int,h:Head| 0<=i<path.len()-1 && #[trigger] load.ensures((&owner,path[i]),Ok(h)) implies
            (h matches Head::Delta{previous,mutations,..} && previous==Some(path[i+1]) &&
                crate::overlay_batch::after_rows(mutations@,mutations.len() as nat,address@,None).is_none()) by {
            assert(i==0 && path[i]==newest && path[i+1]==writer);
            assert(address@!=seq![120u8,0u8,121u8]);
            reveal_with_fuel(crate::overlay_batch::after_rows,2);
        }
    }
    decode_then_reopen(&owner,newest,kind,target,true,&other,load,measure,|_:&u64|(),(lookup,value),|_,_|(),
        page,page,legacy,Ghost(text@),Ghost(path))
}

/// Instantiate the page evidence for an actual decoded leaf and recover its
/// marker with the full walker, merger and store replay.
fn checkpoint_marker_decision(target:Id,kind:Marker) -> (out:Result<Admission,RecoveryError<()>>)
    requires vstd::laws_cmp::obeys_cmp::<Vec<u8>>(),vstd::laws_cmp::obeys_cmp_deep_eq::<Vec<u8>>(),
        obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),
    ensures out matches Ok(decision) && !(decision is Allowed) && (kind is Revoked ==> decision is Revoked),
{
    let ns = kind.namespace().as_bytes();
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
        assert(marker_in_snapshot(kind,target,Some(1u64),read,None));
    }
    match kind {
        Marker::Revoked => reopen_from_pages(Some(1u64),None,read,empty,None,None,target,true,legacy),
        Marker::Consumed => reopen_from_pages(None,Some(1u64),empty,read,None,None,target,true,legacy),
    }
}

spec fn revocation_address(id:Id,text:[u8;36],key:&[u8]) -> bool {
    marker_key::spells(id@,text@) && key@=="caps:revoked".spec_bytes()+seq![0u8]+text@
}

spec fn publication_result<E>(attempt:Result<Option<()>,E>) -> Result<bool,E> {
    match attempt {Err(e)=>Err(e),Ok(done)=>Ok(done.is_some())}
}

/// A persistent revocation reaches one point-write attempt on the header supplied by
/// the blocking tree store. A root conflict requests a retry; it cannot acknowledge the caller.
fn revocation_write_attempt<H,E,R,W>(live:&mut HashMap<Id,token_authority::TokenStatus>,id:Id,header:&H,read:R,publish:W)
    -> (out:Result<Option<()>,E>)
    where R:FnOnce(&H,&[u8])->Result<Option<Vec<u8>>,E>,W:FnOnce(Vec<crate::kv_replacement::Replacement>)->Result<bool,E>,
    requires hash_map_inv(old(live)),obeys_key_model::<Id>(),obeys_concrete_eq::<Id>(),vstd::pervasive::obeys_clone_eq::<Id>(),
        forall|key:&[u8]| #[trigger] read.requires((header,key)),
        forall|rows:Vec<crate::kv_replacement::Replacement>| #[trigger] publish.requires((rows,)),
    ensures final(live)@.contains_key(id) && final(live)@[id].revoked(),
        exists|text:[u8;36],key:&[u8]| #[trigger] revocation_address(id,text,key) && (
                (out matches Err(e) && read.ensures((header,key),Err(e))) ||
                exists|old:Option<Vec<u8>>| #[trigger] read.ensures((header,key),Ok(old)) && (
                    if crate::kv_replacement::bytes(old)==Some(seq![1u8]) {out==Ok(Some(()))}
                    else {exists|rows:Vec<crate::kv_replacement::Replacement>| rows.len()==1 &&
                        rows@[0].fields()==(key@,Some(seq![1u8]),Some((match old {Some(v)=>Some(v.len()),None=>None},false))) &&
                        #[trigger] publish.ensures((rows,),publication_result(out))}
                )
            ),
{
    use crate::kv_replacement::Replacement;
    let uuid=|k:&Id| -> (v:Id) ensures v==*k, {*k};
    let submit=|ns:&'static str,key:[u8;36],value:[u8;1]| -> (r:(&'static str,[u8;36],[u8;1])) ensures r==(ns,key,value), {(ns,key,value)};
    let (ns,text,value)=token_authority::submit_revocation(live,&id,uuid,submit);
    assert(marker_key::spells(id@,text@));
    let address=crate::encoding::composite(ns.as_bytes(),&text);
    let key=address.as_slice();
    assert(revocation_address(id,text,key));
    let r=Replacement::set_at(header,key,&value,read);
    match r {
        Err(e)=>Err(e),
        Ok(((),rows,changed))=>{
            let ghost prior=choose|v:Option<Vec<u8>>| #[trigger] read.ensures((header,key),Ok(v)) &&
                Replacement::assignment(rows@,changed,key@,crate::kv_replacement::bytes(v),value@);
            let result=crate::mutation_ack::finish((),rows,changed,publish);
            result
        }
    }
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
