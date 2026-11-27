//! Component-level witness for physical gate and VFS-relative path reconstruction.
use crate::physical::{PhysicalPath, confine, rebuild};
use crate::mount_selection::VfsTarget;
use vstd::prelude::*;

verus! {
struct Path { components:Vec<u64> }

impl PhysicalPath<u64> for Path {
    closed spec fn parts(&self) -> Seq<u64> { self.components@ }
    closed spec fn pushed(parts:Seq<u64>, name:u64) -> Seq<u64> { parts.push(name) }
    closed spec fn stripped(p:Seq<u64>, r:Seq<u64>) -> Option<Seq<u64>> {
        if r.len() <= p.len() && p.take(r.len() as int) == r {
            Some(p.skip(r.len() as int))
        } else { None }
    }
    fn append(&mut self,n:u64) { self.components.push(n); }
    fn relative(&self,root:&Self) -> (out:Option<Self>) {
        let p = &self.components;
        let r = &root.components;
        if r.len() > p.len() { return None; }
        let mut i = 0;
        while i < r.len()
            invariant p@ == self.components@, r@ == root.components@,
                i <= r.len() <= p.len(), p@.take(i as int) == r@.take(i as int),
            decreases r.len()-i,
        {
            if p[i] != r[i] {
                assert(p@.take(r.len() as int)[i as int] != r@[i as int]);
                return None;
            }
            i += 1;
            assert(p@.take(i as int) =~= r@.take(i as int));
        }
        assert(r@.take(i as int) =~= r@);
        let (_,suffix) = p.as_slice().split_at(i);
        let mut components = Vec::new();
        components.extend_from_slice(suffix);
        Some(Path { components })
    }
}

spec fn ordered(names:Seq<u64>) -> Seq<u64> {
    Seq::new(names.len(), |i:int| names[names.len()-1-i])
}

proof fn order(ancestor:Seq<u64>,names:Seq<u64>)
    ensures rebuild::<u64,Path>(ancestor,names) == ancestor + ordered(names),
    decreases names.len(),
{
    if names.len() > 0 {
        order(ancestor.push(names.last()),names.drop_last());
        assert(ordered(names) =~= seq![names.last()] + ordered(names.drop_last()));
    }
    assert(rebuild::<u64,Path>(ancestor,names) =~= ancestor + ordered(names));
}

fn gated_mount(root:&Path, ancestor:Path, names:Vec<u64>, target:VfsTarget,
    workspace:Option<u64>, home:Option<u64>, tmp:Option<u64>, allowed:bool)
    -> (out:Option<(Path,u64,Path,Vec<u64>)>)
    ensures ({
        let full = ancestor.components@ + ordered(names@);
        let r = root.components@;
        let mount = match target { VfsTarget::Workspace => workspace, VfsTarget::Home => home, VfsTarget::Tmp => tmp };
        let inside = r.len() <= full.len() && full.take(r.len() as int) == r;
        &&& out.is_some() == (inside && allowed && mount.is_some())
        &&& out matches Some((gate,selected,address,checked)) ==> checked@ == full && gate.components@ == full
            && Some(selected) == mount && address.components@ == full.skip(r.len() as int)
            && r + address.components@ == gate.components@
    }),
{
    proof { order(ancestor.components@,names@); }
    match confine(root,ancestor,names) {
        Ok((gate,address)) => match target.admitted(&gate,address,(workspace,home,tmp),(),
            |g:&Path| -> (out:Result<Vec<u64>,()>) ensures match out {
                Ok(guard) => allowed && guard@ == g.components@, Err(_) => !allowed,
            }, {
                if allowed { Ok(g.components.clone()) } else { Err(()) }
            }) {
            Ok((guard,mount,relative)) => {
                assert(root.components@ + relative.components@ =~= gate.components@);
                Some((gate,mount,relative,guard))
            },
            Err(_) => None,
        },
        Err(_) => None,
    }
}
}
