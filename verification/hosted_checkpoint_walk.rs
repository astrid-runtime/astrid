//! Complete per-address key enumeration across any finite decoded checkpoint.
use std::collections::BTreeMap;
use vstd::prelude::*;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_deep_eq},std_specs::btree::btree_map_inv};
use crate::{checkpoint_leaf::{self,Entry,visited},checkpoint_range::{Child,Page,scheduled},
    checkpoint_walk::{self,Contents,History,failed,initial,reached,step},encoding,
    hosted_checkpoint_leaf::{checkpoint_keys,marks}};
type Keys = BTreeMap<Vec<u8>,bool>;
verus! {

spec fn contains<V>(rows:Seq<Entry<V>>,n:nat,key:Seq<u8>,start:Seq<u8>,end:Seq<u8>) -> bool {
    encoding::range_contains(start,end,key) &&
        exists|i:int| 0 <= i < n && (#[trigger] rows[i]).key@ == key
}

proof fn leaf_target<V>(rows:Seq<Entry<V>>,n:nat,key:Seq<u8>,base:Map<Seq<u8>,bool>,start:Seq<u8>,end:Seq<u8>)
    requires n <= rows.len(),
    ensures checkpoint_keys(base,rows,n,start,end).get(key) ==
        if contains(rows,n,key,start,end) { Some(true) } else { base.get(key) },
    decreases n,
{
    if n > 0 {
        leaf_target(rows,(n-1) as nat,key,base,start,end);
        assert(contains(rows,n,key,start,end) == (contains(rows,(n-1) as nat,key,start,end) ||
            (encoding::range_contains(start,end,key) && rows[n-1].key@ == key))) by {
            if contains(rows,n,key,start,end) {
                let i = choose|i:int| 0 <= i < n && (#[trigger] rows[i]).key@ == key;
                assert(i == n-1 || i < n-1);
            }
        }
    }
}

spec fn pending<I,T>(s:Seq<Page<I,T>>,has:spec_fn(Page<I,T>)->bool) -> bool {
    exists|i:int| 0 <= i < s.len() && has(#[trigger] s[i])
}
proof fn combine<I,T>(a:Seq<Page<I,T>>,b:Seq<Page<I,T>>,has:spec_fn(Page<I,T>)->bool)
    ensures pending(a+b,has) == (pending(a,has) || pending(b,has)),
{
    if pending(a+b,has) {
        let i = choose|i:int| 0 <= i < (a+b).len() && has(#[trigger] (a+b)[i]);
        if i < a.len() { assert((a+b)[i] == a[i]); } else { assert((a+b)[i] == b[i-a.len()]); }
    }
    if pending(a,has) {
        let i = choose|i:int| 0 <= i < a.len() && has(#[trigger] a[i]);
        assert((a+b)[i] == a[i]);
    }
    if pending(b,has) {
        let i = choose|i:int| 0 <= i < b.len() && has(#[trigger] b[i]);
        assert((a+b)[a.len()+i] == b[i]);
    }
}

spec fn final_value<I,T>(keys:Keys,s:Seq<Page<I,T>>,key:Seq<u8>,has:spec_fn(Page<I,T>)->bool) -> Option<bool> {
    if pending(s,has) { Some(true) } else { keys.deep_view().get(key) }
}

spec fn image<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(read:R,has:spec_fn(Page<I,T>)->bool,
    key:Seq<u8>,start:Seq<u8>,end:Seq<u8>) -> bool {
    &&& forall|p:Page<I,T>,rows:Vec<Entry<V>>| #[trigger] read.ensures((p,),Ok(Contents::Leaf(rows))) ==>
        has(p) == contains(rows@,rows@.len(),key,start,end)
    &&& forall|p:Page<I,T>,h:u16,c:Vec<Child<I,T>>| #[trigger] read.ensures((p,),Ok(Contents::Branch(h,c))) ==>
        has(p) == pending(scheduled(c@,0,start,end),has)
}

spec fn writer<V,E,F:Fn(Keys,Entry<V>)->Result<Keys,E>>(f:F) -> bool {
    forall|s:Keys,r:Entry<V>,o:Result<Keys,E>| btree_map_inv(&s) && #[trigger] f.ensures((s,r),o) ==>
        match o { Ok(a) => btree_map_inv(&a) && a.deep_view() == s.deep_view().insert(r.key@,true), Err(_) => false }
}

#[verifier::rlimit(20)]
proof fn preserve<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>,F:Fn(Keys,Entry<V>)->Result<Keys,E>>(
    n:History<I,T,Keys>,root:Option<I>,base:Keys,s:Seq<Page<I,T>>,keys:Keys,start:Seq<u8>,end:Seq<u8>,read:R,f:F,
    key:Seq<u8>,has:spec_fn(Page<I,T>)->bool,
)
    requires reached(n,root,base,s,keys,start,end,read,f), btree_map_inv(&base),writer(f),image(read,has,key,start,end),
    ensures btree_map_inv(&keys), final_value(keys,s,key,has) == final_value(base,initial(root),key,has),
    decreases n.len(),
{
    if n.len() == 0 { return; }
    let (prior,before) = n.last();
    let path = n.drop_last();
    let all = n.push((s,keys));
    assert(n =~= path.push((prior,before)));
    assert forall|i:int| 0 <= i < path.len() implies step((#[trigger] n[i]).0,n[i].1,n[i+1].0,n[i+1].1,start,end,read,f) by {
        assert(n[i] == all[i] && n[i+1] == all[i+1]);
    }
    assert(all[n.len()-1] == (prior,before));
    assert(all[n.len() as int] == (s,keys));
    preserve(path,root,base,prior,before,start,end,read,f,key,has);
    assert(step(prior,before,s,keys,start,end,read,f));
    let page = prior.last();
    let rest = prior.drop_last();
    let contents = choose|contents:Contents<I,T,V>| #[trigger] read.ensures((page,),Ok(contents)) &&
        match contents {
            Contents::Leaf(rows) => s == rest && visited(rows@,rows@.len(),start,end,before,keys,f),
            Contents::Branch(_,children) => keys == before && s == rest+scheduled(children@,0,start,end),
        };
    assert(prior =~= rest+seq![page]);
    combine(rest,seq![page],has);
    assert(pending(seq![page],has) == has(page)) by { assert(seq![page][0] == page); }
    assert(read.ensures((page,),Ok(contents)));
    match contents {
        Contents::Leaf(rows) => {
            assert(has(page) == contains(rows@,rows@.len(),key,start,end));
            marks(rows@,rows@.len(),start,end,before,keys,f);
            leaf_target(rows@,rows@.len(),key,before.deep_view(),start,end);
        }
        Contents::Branch(h,c) => { assert(read.ensures((page,),Ok(Contents::Branch(h,c))));
            assert(has(page) == pending(scheduled(c@,0,start,end),has));
            combine(rest,scheduled(c@,0,start,end),has); }
    }
}
}

verus! {
// For each physical address, relate the decoded contents of each page to its
// membership in that page's requested subrange. A successful traversal has
// exactly the presence bit of the root, combined with the caller's input map.
// An error must come from reading a page which the traversal actually reached.
fn enumerate<I,T,V,E,R:Fn(Page<I,T>)->Result<Contents<I,T,V>,E>>(
    root:Option<I>,start:&[u8],end:&[u8],keys:Keys,read:R,
    Ghost(key):Ghost<Seq<u8>>,Ghost(has):Ghost<spec_fn(Page<I,T>)->bool>,
) -> (out:Result<Keys,E>)
    requires btree_map_inv(&keys),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
        forall|p:Page<I,T>| #[trigger] read.requires((p,)),image(read,has,key,start@,end@),
        forall|p:Page<I,T>,h:u16,c:Vec<Child<I,T>>| #[trigger] read.ensures((p,),Ok(Contents::Branch(h,c))) ==>
            h > 0 && (p matches Page::Child(child) ==> child.level == h) &&
            forall|i:int| 0 <= i < c.len() ==> (#[trigger] c@[i]).level as nat+1 == h,
    ensures match out {
        Ok(after) => btree_map_inv(&after) && after.deep_view().get(key) == if root matches Some(id) && has(Page::Root(id)) {
            Some(true)
        } else { keys.deep_view().get(key) },
        Err(e) => exists|history:History<I,T,Keys>,stack:Seq<Page<I,T>>,s:Keys|
            #[trigger] reached(history,root,keys,stack,s,start@,end@,read,checkpoint_leaf::mark::<V,E>) &&
            stack.len()>0 && read.ensures((stack.last(),),Err(e)),
    },
{
    let f = checkpoint_leaf::mark::<V,E>;
    assert(writer(f));
    assert forall|n:History<I,T,Keys>,stack:Seq<Page<I,T>>,s:Keys,rows:Vec<Entry<V>>,i:int,prior:Keys|
        #[trigger] reached(n,root,keys,stack,s,start@,end@,read,f) && stack.len()>0 &&
        #[trigger] read.ensures((stack.last(),),Ok(Contents::Leaf(rows))) &&
        0 <= i < rows.len() && #[trigger] visited(rows@,i as nat,start@,end@,s,prior,f) &&
        encoding::range_contains(start@,end@,rows@[i].key@) implies f.requires((prior,rows@[i])) by {
        preserve(n,root,keys,stack,s,start@,end@,read,f,key,has);
        marks(rows@,i as nat,start@,end@,s,prior,f);
    }
    let out = checkpoint_walk::fold(root,start,end,keys,read,f);
    let ghost observed = out;
    let ghost origin = root;
    proof {
        match observed {
            Ok(after) => {
                let n = choose|n:History<I,T,Keys>| #[trigger] reached(n,root,keys,Seq::empty(),after,start@,end@,read,f);
                preserve(n,root,keys,Seq::empty(),after,start@,end@,read,f,key,has);
                if let Some(id) = origin { assert(initial::<I,T>(origin)[0] == Page::Root(id)); }
            }
            Err(e) => {
                let (n,stack,s) = choose|n:History<I,T,Keys>,stack:Seq<Page<I,T>>,s:Keys|
                    #[trigger] reached(n,root,keys,stack,s,start@,end@,read,f) &&
                    failed(stack,s,start@,end@,read,f,e);
                preserve(n,root,keys,stack,s,start@,end@,read,f,key,has);
                if !read.ensures((stack.last(),),Err(e)) {
                    let (rows,i,prior) = choose|rows:Vec<Entry<V>>,i:int,prior:Keys|
                        #[trigger] read.ensures((stack.last(),),Ok(Contents::Leaf(rows))) &&
                        0 <= i < rows.len() && visited(rows@,i as nat,start@,end@,s,prior,f) &&
                        encoding::range_contains(start@,end@,rows@[i].key@) && #[trigger] f.ensures((prior,rows@[i]),Err(e));
                    marks(rows@,i as nat,start@,end@,s,prior,f);
                    assert(btree_map_inv(&prior));
                    assert(f.ensures((prior,rows@[i]),Err(e)));
                    assert(writer(f));
                    assert(false);
                }
                assert(read.ensures((stack.last(),),Err(e)));
            }
        }
    }
    out
}
}
