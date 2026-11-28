//! Finish the wrapper options after mounts, before the guest executable and argv.
use vstd::prelude::*;

verus! {

pub(super) fn finish<A,F:Fn(&'static str)->A>(args: &mut Vec<A>, network: bool, encode:F)
    requires forall|s:&'static str| #[trigger] encode.requires((s,)),
    ensures ({
        let before = old(args)@;
        let after = final(args)@;
        let i = before.len() as int;
        &&& after.take(i) == before
        &&& after.len() == i + (if network { 4int } else { 3int })
        &&& encode.ensures(("--unshare-all",),after[i])
        &&& network ==> encode.ensures(("--share-net",),after[i+1])
        &&& encode.ensures(("--die-with-parent",),after[after.len()-2])
        &&& encode.ensures(("--",),after.last())
    }),
{
    args.push(encode("--unshare-all"));
    if network { args.push(encode("--share-net")); }
    args.push(encode("--die-with-parent"));
    args.push(encode("--"));
}

}
